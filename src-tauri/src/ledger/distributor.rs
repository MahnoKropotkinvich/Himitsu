use crate::error::Result;
use crate::storage::db::Database;
use crate::storage::models::{LedgerAction, LedgerEntry};
use crate::storage::schema::CF_LEDGER;

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

/// Retrieve all ledger entries (newest first).
pub fn list_all(db: &Database) -> Result<Vec<LedgerEntry>> {
    let raw = db.iter_cf(CF_LEDGER)?;
    let mut entries: Vec<LedgerEntry> = raw
        .iter()
        .filter_map(|(_k, v)| bincode::deserialize(v).ok())
        .collect();
    entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
    Ok(entries)
}

/// Search ledger entries by user_id substring.
pub fn search_by_user(db: &Database, query: &str) -> Result<Vec<LedgerEntry>> {
    let all = list_all(db)?;
    let query_lower = query.to_lowercase();
    Ok(all
        .into_iter()
        .filter(|e| {
            e.user_id.to_lowercase().contains(&query_lower)
                || e.gpg_fingerprint.to_lowercase().contains(&query_lower)
        })
        .collect())
}
