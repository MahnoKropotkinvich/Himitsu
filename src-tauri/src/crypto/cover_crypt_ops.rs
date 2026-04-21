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

/// 1 MiB chunk size for parallel AES-GCM.
const CHUNK_SIZE: usize = 1 << 20;

/// Encrypted payload: header (CoverCrypt encapsulation) + chunked AES-GCM ciphertext.
///
/// Serialized with bincode for compact binary representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BroadcastCiphertext {
    pub header: Vec<u8>,
    /// 8-byte base nonce.  Per-chunk nonce = base_nonce(8) || chunk_index(4 BE).
    pub nonce: Vec<u8>,
    pub policy: String,
    /// Whether the plaintext was zstd-compressed before chunking.
    pub compressed: bool,
    /// Per-chunk encrypted blobs.
    pub chunks: Vec<Vec<u8>>,
    /// Chunk size in bytes used during encryption.
    pub chunk_size: usize,
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
/// Pipeline: zstd-compress (multi-threaded) → split into 1 MiB chunks →
/// AES-256-GCM encrypt each chunk in parallel via rayon.
///
/// Each chunk uses a unique 12-byte nonce: `base_nonce(8) || chunk_index(4 BE)`.
pub fn encrypt(
    mpk_bytes: &[u8],
    policy_str: &str,
    plaintext: &[u8],
) -> Result<BroadcastCiphertext> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    use rayon::prelude::*;

    let cc = Covercrypt::default();
    let mpk = de_mpk(mpk_bytes)?;
    let ap = AccessPolicy::parse(policy_str).map_err(map_cc_err)?;

    // 0. Compress plaintext with zstd (level 3, multi-threaded)
    let compressed = {
        use std::io::Write;
        let mut encoder = zstd::Encoder::new(Vec::new(), 3)
            .map_err(|e| HimitsuError::Broadcast(format!("zstd encoder init: {e}")))?;
        encoder
            .set_parameter(zstd::zstd_safe::CParameter::NbWorkers(num_cpus::get() as u32))
            .map_err(|e| HimitsuError::Broadcast(format!("zstd set NbWorkers: {e}")))?;
        encoder
            .write_all(plaintext)
            .map_err(|e| HimitsuError::Broadcast(format!("zstd write: {e}")))?;
        encoder
            .finish()
            .map_err(|e| HimitsuError::Broadcast(format!("zstd finish: {e}")))?
    };

    tracing::debug!(
        original = plaintext.len(),
        compressed = compressed.len(),
        ratio = format!("{:.1}%", compressed.len() as f64 / plaintext.len().max(1) as f64 * 100.0),
        "zstd compression"
    );

    // 1. CoverCrypt header → shared secret
    let (secret, encrypted_header) =
        EncryptedHeader::generate(&cc, &mpk, &ap, None, None)
            .map_err(map_cc_err)?;

    // 2. Split compressed data into chunks and encrypt in parallel
    let base_nonce: [u8; 8] = rand::random();
    let key = Key::<Aes256Gcm>::from_slice(&*secret);

    let chunk_results: Vec<std::result::Result<Vec<u8>, String>> = compressed
        .par_chunks(CHUNK_SIZE)
        .enumerate()
        .map(|(idx, chunk)| {
            let cipher = Aes256Gcm::new(key);
            let mut nonce_buf = [0u8; 12];
            nonce_buf[..8].copy_from_slice(&base_nonce);
            nonce_buf[8..12].copy_from_slice(&(idx as u32).to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_buf);
            cipher
                .encrypt(nonce, chunk)
                .map_err(|e| format!("AES-GCM encrypt chunk {idx}: {e}"))
        })
        .collect();

    // Collect results, propagate first error
    let encrypted_chunks: Vec<Vec<u8>> = chunk_results
        .into_iter()
        .collect::<std::result::Result<Vec<_>, String>>()
        .map_err(|e| HimitsuError::Broadcast(e))?;

    tracing::debug!(
        num_chunks = encrypted_chunks.len(),
        chunk_size = CHUNK_SIZE,
        "Parallel AES-GCM encryption"
    );

    Ok(BroadcastCiphertext {
        header: ser_header(&encrypted_header)?,
        nonce: base_nonce.to_vec(),
        policy: policy_str.to_string(),
        compressed: true,
        chunks: encrypted_chunks,
        chunk_size: CHUNK_SIZE,
    })
}

/// Decrypt a `BroadcastCiphertext` using a user secret key.
///
/// Supports both chunked (new) and single-blob (legacy) formats.
/// Chunks are decrypted in parallel via rayon, then reassembled and
/// zstd-decompressed if the ciphertext was compressed.
pub fn decrypt(
    usk_bytes: &[u8],
    broadcast_ct: &BroadcastCiphertext,
) -> Result<Vec<u8>> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};
    use rayon::prelude::*;

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

    let key = Key::<Aes256Gcm>::from_slice(&*cleartext_header.secret);

    // 2. Parallel chunked decryption
    let base_nonce = &broadcast_ct.nonce;

    let chunk_results: Vec<std::result::Result<Vec<u8>, String>> = broadcast_ct
        .chunks
        .par_iter()
        .enumerate()
        .map(|(idx, enc_chunk)| {
            let cipher = Aes256Gcm::new(key);
            let mut nonce_buf = [0u8; 12];
            nonce_buf[..8].copy_from_slice(base_nonce);
            nonce_buf[8..12].copy_from_slice(&(idx as u32).to_be_bytes());
            let nonce = Nonce::from_slice(&nonce_buf);
            cipher
                .decrypt(nonce, enc_chunk.as_ref())
                .map_err(|e| format!("AES-GCM decrypt chunk {idx}: {e}"))
        })
        .collect();

    let plain_chunks: Vec<Vec<u8>> = chunk_results
        .into_iter()
        .collect::<std::result::Result<Vec<_>, String>>()
        .map_err(|e| HimitsuError::Decryption(e))?;

    tracing::debug!(num_chunks = plain_chunks.len(), "Parallel AES-GCM decryption");

    // Reassemble in order
    let total: usize = plain_chunks.iter().map(|c| c.len()).sum();
    let mut decrypted = Vec::with_capacity(total);
    for chunk in plain_chunks {
        decrypted.extend_from_slice(&chunk);
    }

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
