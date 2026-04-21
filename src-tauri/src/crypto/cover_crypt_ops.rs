//! CoverCrypt broadcast encryption wrapper.
//!
//! Provides setup, key generation, encryption, decryption, and revocation
//! via the cosmian_cover_crypt crate.  All keys are serialized via the
//! Serializable trait from cosmian_crypto_core.

use cosmian_cover_crypt::{
    api::Covercrypt,
    encrypted_header::EncryptedHeader,
    AccessPolicy, EncryptionHint,
    MasterPublicKey, MasterSecretKey, QualifiedAttribute, UserSecretKey,
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use serde::{Deserialize, Serialize};

use crate::error::{HimitsuError, Result};

/// Serialized master key pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastKeyPair {
    pub master_secret_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Serialized user secret key with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedUserKey {
    pub user_id: String,
    pub access_policy: String,
    pub key_data: Vec<u8>,
}

/// Encrypted payload: header (CoverCrypt encapsulation) + AES-GCM ciphertext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastCiphertext {
    pub header: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub policy: String,
    /// Whether the plaintext was zstd-compressed before encryption.
    /// Defaults to false for backward compatibility with old ciphertexts.
    #[serde(default)]
    pub compressed: bool,
}

// ---------------------------------------------------------------------------
// Helpers: serialize/deserialize CoverCrypt types via Serializable trait
// ---------------------------------------------------------------------------

fn ser_msk(msk: &MasterSecretKey) -> Result<Vec<u8>> {
    Ok(msk.serialize().map_err(map_cc_err)?.to_vec())
}
fn de_msk(data: &[u8]) -> Result<MasterSecretKey> {
    MasterSecretKey::deserialize(data).map_err(map_cc_err)
}
fn ser_mpk(mpk: &MasterPublicKey) -> Result<Vec<u8>> {
    Ok(mpk.serialize().map_err(map_cc_err)?.to_vec())
}
fn de_mpk(data: &[u8]) -> Result<MasterPublicKey> {
    MasterPublicKey::deserialize(data).map_err(map_cc_err)
}
fn ser_usk(usk: &UserSecretKey) -> Result<Vec<u8>> {
    Ok(usk.serialize().map_err(map_cc_err)?.to_vec())
}
fn de_usk(data: &[u8]) -> Result<UserSecretKey> {
    UserSecretKey::deserialize(data).map_err(map_cc_err)
}
fn ser_header(h: &EncryptedHeader) -> Result<Vec<u8>> {
    Ok(h.serialize().map_err(map_cc_err)?.to_vec())
}
fn de_header(data: &[u8]) -> Result<EncryptedHeader> {
    EncryptedHeader::deserialize(data).map_err(map_cc_err)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Set up the CoverCrypt system.
///
/// `dimensions` is a list of (name, is_hierarchical, attributes) tuples.
/// For hierarchical dimensions, attributes are listed from lowest to highest.
pub fn setup(
    dimensions: &[(String, bool, Vec<String>)],
) -> Result<BroadcastKeyPair> {
    let cc = Covercrypt::default();
    let (mut msk, _) = cc.setup().map_err(map_cc_err)?;

    for (dim_name, hierarchical, attrs) in dimensions {
        if *hierarchical {
            msk.access_structure
                .add_hierarchy(dim_name.clone())
                .map_err(map_cc_err)?;
            let mut prev: Option<&str> = None;
            for attr_name in attrs {
                msk.access_structure
                    .add_attribute(
                        QualifiedAttribute::new(dim_name, attr_name),
                        EncryptionHint::Classic,
                        prev,
                    )
                    .map_err(map_cc_err)?;
                prev = Some(attr_name);
            }
        } else {
            msk.access_structure
                .add_anarchy(dim_name.clone())
                .map_err(map_cc_err)?;
            for attr_name in attrs {
                msk.access_structure
                    .add_attribute(
                        QualifiedAttribute::new(dim_name, attr_name),
                        EncryptionHint::Classic,
                        None,
                    )
                    .map_err(map_cc_err)?;
            }
        }
    }

    let mpk = cc.update_msk(&mut msk).map_err(map_cc_err)?;

    Ok(BroadcastKeyPair {
        master_secret_key: ser_msk(&msk)?,
        public_key: ser_mpk(&mpk)?,
    })
}

/// Generate a user decryption key for the given access policy string.
///
/// Returns the wrapped user key AND the updated MSK (CoverCrypt mutates
/// the MSK during keygen).
pub fn generate_user_key(
    msk_bytes: &[u8],
    access_policy_str: &str,
    user_id: &str,
) -> Result<(WrappedUserKey, Vec<u8>)> {
    let cc = Covercrypt::default();
    let mut msk = de_msk(msk_bytes)?;
    let ap = AccessPolicy::parse(access_policy_str).map_err(map_cc_err)?;

    let usk = cc
        .generate_user_secret_key(&mut msk, &ap)
        .map_err(map_cc_err)?;

    let wrapped = WrappedUserKey {
        user_id: user_id.to_string(),
        access_policy: access_policy_str.to_string(),
        key_data: ser_usk(&usk)?,
    };
    let updated_msk = ser_msk(&msk)?;
    Ok((wrapped, updated_msk))
}

/// Encrypt plaintext under an access policy.
///
/// The plaintext is zstd-compressed before encryption to reduce ciphertext
/// size.  Returns a `BroadcastCiphertext` containing the CoverCrypt header
/// and AES-256-GCM encrypted payload.
pub fn encrypt(
    mpk_bytes: &[u8],
    policy_str: &str,
    plaintext: &[u8],
) -> Result<BroadcastCiphertext> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};

    let cc = Covercrypt::default();
    let mpk = de_mpk(mpk_bytes)?;
    let ap = AccessPolicy::parse(policy_str).map_err(map_cc_err)?;

    // 0. Compress plaintext with zstd (level 3 = good balance)
    let compressed = zstd::encode_all(plaintext, 3)
        .map_err(|e| HimitsuError::Broadcast(format!("zstd compress failed: {e}")))?;

    tracing::debug!(
        original = plaintext.len(),
        compressed = compressed.len(),
        ratio = format!("{:.1}%", compressed.len() as f64 / plaintext.len().max(1) as f64 * 100.0),
        "zstd compression"
    );

    // 1. Generate encrypted header encapsulating a shared secret
    let (secret, encrypted_header) =
        EncryptedHeader::generate(&cc, &mpk, &ap, None, None)
            .map_err(map_cc_err)?;

    // 2. Use the 32-byte shared secret as AES-256-GCM key
    let key = Key::<Aes256Gcm>::from_slice(&*secret);
    let cipher = Aes256Gcm::new(key);
    let nonce_bytes: [u8; 12] = rand::random();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, compressed.as_ref())
        .map_err(|e| HimitsuError::Broadcast(format!("AES-GCM encrypt failed: {e}")))?;

    Ok(BroadcastCiphertext {
        header: ser_header(&encrypted_header)?,
        ciphertext,
        nonce: nonce_bytes.to_vec(),
        policy: policy_str.to_string(),
        compressed: true,
    })
}

/// Decrypt a `BroadcastCiphertext` using a user secret key.
///
/// If the ciphertext was compressed (all new ciphertexts are), the plaintext
/// is automatically zstd-decompressed.  Old uncompressed ciphertexts are
/// handled transparently.
///
/// Returns the plaintext bytes, or an error if the user's access policy
/// does not satisfy the encryption policy.
pub fn decrypt(
    usk_bytes: &[u8],
    broadcast_ct: &BroadcastCiphertext,
) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};

    let cc = Covercrypt::default();
    let usk = de_usk(usk_bytes)?;
    let encrypted_header = de_header(&broadcast_ct.header)?;

    // 1. Decapsulate the shared secret from the header
    let cleartext_header = encrypted_header
        .decrypt(&cc, &usk, None)
        .map_err(map_cc_err)?
        .ok_or_else(|| {
            HimitsuError::Decryption(
                "Access denied: user key does not satisfy encryption policy".into(),
            )
        })?;

    // 2. Use the shared secret to decrypt the AES-GCM payload
    let key = Key::<Aes256Gcm>::from_slice(&*cleartext_header.secret);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&broadcast_ct.nonce);
    let decrypted = cipher
        .decrypt(nonce, broadcast_ct.ciphertext.as_ref())
        .map_err(|e| HimitsuError::Decryption(format!("AES-GCM decrypt failed: {e}")))?;

    // 3. Decompress if needed
    if broadcast_ct.compressed {
        let plaintext = zstd::decode_all(decrypted.as_slice())
            .map_err(|e| HimitsuError::Decryption(format!("zstd decompress failed: {e}")))?;
        tracing::debug!(
            compressed = decrypted.len(),
            decompressed = plaintext.len(),
            "zstd decompression"
        );
        Ok(plaintext)
    } else {
        Ok(decrypted)
    }
}

/// Rekey (revoke) all attributes matching the given access policy.
///
/// After rekeying, existing user keys cannot decrypt new ciphertexts
/// until they are refreshed.  Returns updated (MSK, MPK) bytes.
pub fn rekey(
    msk_bytes: &[u8],
    revoke_policy_str: &str,
) -> Result<BroadcastKeyPair> {
    let cc = Covercrypt::default();
    let mut msk = de_msk(msk_bytes)?;
    let ap = AccessPolicy::parse(revoke_policy_str).map_err(map_cc_err)?;

    let mpk = cc.rekey(&mut msk, &ap).map_err(map_cc_err)?;

    Ok(BroadcastKeyPair {
        master_secret_key: ser_msk(&msk)?,
        public_key: ser_mpk(&mpk)?,
    })
}

/// Refresh a user's secret key after a revocation / rekey event.
///
/// If `keep_old_secrets` is false, the user loses the ability to decrypt
/// ciphertexts produced before the rekey.
/// Returns (updated_msk_bytes, updated_usk_bytes).
pub fn refresh_user_key(
    msk_bytes: &[u8],
    usk_bytes: &[u8],
    keep_old_secrets: bool,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let cc = Covercrypt::default();
    let mut msk = de_msk(msk_bytes)?;
    let mut usk = de_usk(usk_bytes)?;

    cc.refresh_usk(&mut msk, &mut usk, keep_old_secrets)
        .map_err(map_cc_err)?;

    Ok((ser_msk(&msk)?, ser_usk(&usk)?))
}

fn map_cc_err(e: cosmian_cover_crypt::Error) -> HimitsuError {
    HimitsuError::Broadcast(e.to_string())
}
