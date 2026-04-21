//! Data models shared across the application.
//!
//! All serializable structs and enums live here to avoid circular
//! dependencies between layers.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ---------------------------------------------------------------------------
// Subscriber / distributor models
// ---------------------------------------------------------------------------

/// A registered subscriber (key recipient).
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

/// BGW user key record (bundled with index for GPG-encrypted distribution).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserKeyRecord {
    pub user_id: String,
    pub bgw_index: u32,
    /// Raw BGW private key bytes (PBC element serialized).
    pub key_data: Vec<u8>,
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

/// Fingerprint vector assigned to a user for traitor tracing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintRecord {
    pub user_id: String,
    pub vector: Vec<i64>,
    pub code_length: usize,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// Ledger
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Rendering / frontend response types
// ---------------------------------------------------------------------------

/// How the frontend should handle decrypted content.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind")]
pub enum RenderAction {
    /// Content can be rendered inline by the WebView.
    Inline {
        mime: String,
        extension: String,
        data_base64: String,
        data_url: String,
        category: InlineCategory,
    },
    /// Content must be opened with an external system application.
    External {
        mime: String,
        extension: String,
        temp_path: String,
    },
    /// File type unknown; provide raw hex preview + option to save.
    Unknown {
        size_bytes: usize,
        hex_preview: String,
    },
}

/// What kind of inline rendering the frontend should use.
#[derive(Debug, Clone, Serialize)]
pub enum InlineCategory {
    Image,
    Video,
    Audio,
    Text,
    Pdf,
    /// Non-renderable binary; frontend shows file info + Save/Clear.
    Binary,
}

/// Result returned to the frontend after decryption.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptResult {
    pub success: bool,
    pub size_bytes: usize,
    pub render: RenderAction,
    pub message: String,
}

/// Basic file info returned for display, with optional inline preview.
#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub size: u64,
    pub name: String,
    pub mime: String,
    pub category: String,
    pub is_dir: bool,
    pub preview_base64: Option<String>,
    pub preview_data_url: Option<String>,
}

/// Result of file encryption.
#[derive(Debug, Clone, Serialize)]
pub struct EncryptFileResult {
    pub input_size: u64,
    pub output_size: u64,
    pub output_path: String,
}

/// Result of file decryption.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptFileResult {
    pub size: usize,
    pub mime: String,
    pub extension: String,
    pub temp_path: String,
    pub category: String,
    pub preview_base64: Option<String>,
    pub preview_data_url: Option<String>,
}

/// Receiver key info for listing in the frontend.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiverKeyInfo {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub active: bool,
    pub bgw_index: u32,
}

/// Result of a GPG key import.
#[derive(Debug, Clone, Serialize)]
pub struct ImportResult {
    pub user_id: String,
    pub fingerprint: String,
    pub display_name: String,
}
