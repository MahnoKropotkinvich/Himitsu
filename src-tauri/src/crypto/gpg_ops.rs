use crate::error::{HimitsuError, Result};

/// Import and parse an ASCII-armored GPG public key.
pub fn parse_public_key(armored: &str) -> Result<pgp::composed::SignedPublicKey> {
    use pgp::composed::signed_key::SignedPublicKey;
    use pgp::Deserializable;

    let (key, _headers) = SignedPublicKey::from_string(armored)
        .map_err(|e| HimitsuError::Gpg(format!("Failed to parse GPG public key: {e}")))?;

    key.verify()
        .map_err(|e| HimitsuError::Gpg(format!("GPG key verification failed: {e}")))?;

    Ok(key)
}

/// Import and parse an ASCII-armored GPG secret key.
pub fn parse_secret_key(armored: &str) -> Result<pgp::composed::SignedSecretKey> {
    use pgp::composed::signed_key::SignedSecretKey;
    use pgp::Deserializable;

    let (key, _headers) = SignedSecretKey::from_string(armored)
        .map_err(|e| HimitsuError::Gpg(format!("Failed to parse GPG secret key: {e}")))?;

    key.verify()
        .map_err(|e| HimitsuError::Gpg(format!("GPG secret key verification failed: {e}")))?;

    Ok(key)
}

/// Get the primary fingerprint of a signed public key as a hex string.
pub fn fingerprint_hex(key: &pgp::composed::SignedPublicKey) -> String {
    use pgp::types::PublicKeyTrait;
    let fp = key.fingerprint();
    match fp {
        pgp::types::Fingerprint::V4(bytes) => hex::encode(bytes),
        pgp::types::Fingerprint::V5(bytes) => hex::encode(bytes),
        pgp::types::Fingerprint::V6(bytes) => hex::encode(bytes),
        _ => "unknown".to_string(),
    }
}

/// Encrypt arbitrary binary data to a GPG public key.
///
/// GPG keys typically have a signing primary key (EdDSA/RSA) and a separate
/// encryption subkey (ECDH/X25519/RSA).  This function selects the first
/// encryption-capable subkey; if none exists it falls back to the primary key.
pub fn encrypt_to_key(
    data: &[u8],
    public_key: &pgp::composed::SignedPublicKey,
) -> Result<Vec<u8>> {
    use pgp::composed::message::Message;
    use pgp::crypto::sym::SymmetricKeyAlgorithm;
    use pgp::types::PublicKeyTrait;

    let msg = Message::new_literal_bytes("encrypted.bin", data);

    // Find an encryption-capable subkey (ECDH, X25519, RSA-encrypt, etc.)
    // The primary key on Ed25519 keys is EdDSALegacy which is sign-only.
    let enc_subkey = public_key
        .public_subkeys
        .iter()
        .find(|sk| sk.key.is_encryption_key());

    let encrypted = if let Some(subkey) = enc_subkey {
        // Use the inner packet::PublicSubkey directly
        msg.encrypt_to_keys_seipdv1(
            &mut rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            &[&subkey.key],
        )
    } else {
        // Fallback: primary key (works for RSA-only keys)
        msg.encrypt_to_keys_seipdv1(
            &mut rand::thread_rng(),
            SymmetricKeyAlgorithm::AES256,
            &[&public_key.primary_key],
        )
    }
    .map_err(|e| HimitsuError::Gpg(format!("Encryption failed: {e}")))?;

    let armored = encrypted
        .to_armored_bytes(None.into())
        .map_err(|e| HimitsuError::Gpg(format!("Armor encoding failed: {e}")))?;

    Ok(armored)
}

/// Decrypt a GPG-encrypted message using a secret key and passphrase.
///
/// Accepts ASCII-armored PGP message bytes and returns the raw plaintext.
pub fn decrypt_with_secret_key(
    encrypted_armored: &[u8],
    secret_key: &pgp::composed::SignedSecretKey,
    passphrase: &str,
) -> Result<Vec<u8>> {
    use pgp::composed::message::Message;
    use pgp::Deserializable;

    let (msg, _) = Message::from_armor_single(encrypted_armored)
        .map_err(|e| HimitsuError::Gpg(format!("Failed to parse encrypted message: {e}")))?;

    let (decrypted_msg, _ids) = msg
        .decrypt(|| passphrase.to_string(), &[secret_key])
        .map_err(|e| HimitsuError::Gpg(format!("Decryption failed: {e}")))?;

    // get_content() handles decompression automatically
    let body = decrypted_msg
        .get_content()
        .map_err(|e| HimitsuError::Gpg(format!("Failed to extract content: {e}")))?
        .ok_or_else(|| HimitsuError::Gpg("Decrypted body is empty".into()))?;

    Ok(body)
}
