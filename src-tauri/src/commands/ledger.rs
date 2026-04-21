//! Distribution ledger: recording and querying events.

use tauri::State;

use crate::AppState;
use crate::error::Result;
use crate::storage::db::Database;
use crate::storage::models::{LedgerAction, LedgerEntry};
use crate::storage::schema::CF_LEDGER;

// ---------------------------------------------------------------------------
// Recording (called internally by other commands)
// ---------------------------------------------------------------------------

/// Record a distribution event in the ledger.
pub fn record(
    db: &Database,
    user_id: &str,
    gpg_fingerprint: &str,
    action: LedgerAction,
    policy_attributes: Vec<String>,
    notes: Option<String>,
) -> Result<String> {
    let id = uuid::Uuid::new_v4().to_string();
    let entry = LedgerEntry {
        id: id.clone(),
        user_id: user_id.to_string(),
        gpg_fingerprint: gpg_fingerprint.to_string(),
        action,
        timestamp: chrono::Utc::now(),
        policy_attributes,
        notes,
    };

    let value = bincode::serialize(&entry)?;
    let key = format!("{}:{}", entry.timestamp.timestamp_millis(), user_id);
    db.put_cf(CF_LEDGER, key.as_bytes(), &value)?;

    Ok(id)
}

// ---------------------------------------------------------------------------
// Tauri commands (called from frontend)
// ---------------------------------------------------------------------------

/// Retrieve all ledger entries (newest first).
#[tauri::command]
pub fn get_ledger_entries(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<LedgerEntry>, String> {
    let db = state.db.lock().unwrap();
    let raw = db.iter_cf(CF_LEDGER).map_err(|e| e.to_string())?;
    let mut entries: Vec<LedgerEntry> = raw
        .iter()
        .filter_map(|(_k, v)| bincode::deserialize(v).ok())
        .collect();
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(entries)
}

/// Search ledger entries by user_id or fingerprint substring.
#[tauri::command]
pub fn search_ledger(
    query: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<LedgerEntry>, String> {
    let db = state.db.lock().unwrap();
    let raw = db.iter_cf(CF_LEDGER).map_err(|e| e.to_string())?;
    let mut entries: Vec<LedgerEntry> = raw
        .iter()
        .filter_map(|(_k, v)| bincode::deserialize(v).ok())
        .collect();
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    let query_lower = query.to_lowercase();
    Ok(entries
        .into_iter()
        .filter(|e| {
            e.user_id.to_lowercase().contains(&query_lower)
                || e.gpg_fingerprint.to_lowercase().contains(&query_lower)
        })
        .collect())
}
