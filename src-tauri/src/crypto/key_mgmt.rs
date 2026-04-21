//! Key lifecycle helpers: wrapping CoverCrypt user keys with GPG,
//! and serialization utilities.

use crate::error::Result;

/// Wrap (encrypt) a CoverCrypt user secret key using the applicant's
/// GPG public key, so it can be safely transmitted.
pub fn wrap_user_key_with_gpg(
    user_secret_key: &[u8],
    gpg_public_key: &pgp::composed::SignedPublicKey,
) -> Result<Vec<u8>> {
    crate::crypto::gpg_ops::encrypt_to_key(user_secret_key, gpg_public_key)
}
