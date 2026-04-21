use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

/// A registered applicant / key recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Applicant {
    pub user_id: String,
    pub display_name: String,
    pub gpg_fingerprint: String,
    pub gpg_public_key_armored: String,
    pub created_at: DateTime<Utc>,
    pub revoked: bool,
    /// BGW user slot index (0..N-1).
    pub bgw_index: u32,
}

/// BGW user key record stored in DB.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyRecord {
    pub user_id: String,
    pub bgw_index: u32,
    /// Raw BGW private key bytes (PBC element serialized).
    pub key_data: Vec<u8>,
}

/// Actions recorded in the distribution ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LedgerAction {
    KeyIssued,
    KeyRevoked,
    CiphertextCreated,
}

/// A single ledger entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: String,
    pub user_id: String,
    pub gpg_fingerprint: String,
    pub action: LedgerAction,
    pub timestamp: DateTime<Utc>,
    pub policy_attributes: Vec<String>,
    pub notes: Option<String>,
}

/// Fingerprint vector assigned to a user for traitor tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintRecord {
    pub user_id: String,
    pub vector: Vec<i64>,
    pub code_length: usize,
    pub created_at: DateTime<Utc>,
}

/// A saved receiver decryption key (BGW private key + user index).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverKey {
    pub id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    /// BGW user slot index.
    pub bgw_index: u32,
    /// Raw BGW private key bytes.
    pub usk_bytes: Vec<u8>,
}

/// Result returned to the frontend after decryption.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptResult {
    pub success: bool,
    pub size_bytes: usize,
    pub render: crate::commands::file_opener::RenderAction,
    pub message: String,
}
