/// RocksDB column family names used to logically partition data.

pub const CF_GPG_KEYS: &str = "gpg_keys";
/// BGW broadcast system state (pairing params + all keys).
/// NOTE: the on-disk CF name remains "cc_master" for backward compatibility
/// with existing databases. The Rust constant name reflects the actual content.
pub const CF_BGW_SYSTEM: &str = "cc_master";
pub const CF_USER_KEYS: &str = "user_keys";
/// GPG-encrypted user key blobs ready for distribution.
pub const CF_ENCRYPTED_KEYS: &str = "encrypted_keys";
pub const CF_FINGERPRINTS: &str = "fingerprints";
pub const CF_CIPHERTEXTS: &str = "ciphertexts";
pub const CF_LEDGER: &str = "ledger";
/// The local receiver's decrypted user secret key.
pub const CF_RECEIVER: &str = "receiver";
pub const CF_CONFIG: &str = "config";

/// All column families that must exist when the database is opened.
pub const ALL_CFS: &[&str] = &[
    CF_GPG_KEYS,
    CF_BGW_SYSTEM,
    CF_USER_KEYS,
    CF_ENCRYPTED_KEYS,
    CF_FINGERPRINTS,
    CF_CIPHERTEXTS,
    CF_LEDGER,
    CF_RECEIVER,
    CF_CONFIG,
];
