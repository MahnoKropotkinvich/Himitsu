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
}

/// Actions recorded in the distribution ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LedgerAction {
    KeyIssued,
    KeyRevoked,
    KeyRefreshed,
    CiphertextCreated,
}

/// A single ledger entry tracking who received what key and when.
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

/// Metadata stored alongside a ciphertext blob.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiphertextMeta {
    pub id: String,
    pub policy: String,
    pub created_at: DateTime<Utc>,
    pub creator_note: Option<String>,
}

/// Fingerprint vector assigned to a user for traitor tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintRecord {
    pub user_id: String,
    pub vector: Vec<i64>,
    pub code_length: usize,
    pub created_at: DateTime<Utc>,
}

/// A saved receiver decryption key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiverKey {
    pub id: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    /// Decrypted CoverCrypt USK bytes.
    pub usk_bytes: Vec<u8>,
}

/// Result returned to the frontend after decryption.
///
/// Contains the render action that tells the frontend how to display
/// the content (inline via data-URI, external app, or raw hex).
#[derive(Debug, Clone, Serialize)]
pub struct DecryptResult {
    pub success: bool,
    pub size_bytes: usize,
    pub render: crate::commands::file_opener::RenderAction,
    pub message: String,
}
