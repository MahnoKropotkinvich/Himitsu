use tauri::State;
use crate::AppState;
use crate::storage::models::LedgerEntry;
use crate::ledger::distributor;

/// Get all ledger entries.
#[tauri::command]
pub fn get_ledger_entries(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<LedgerEntry>, String> {
    let db = state.db.lock().unwrap();
    distributor::list_all(&db).map_err(|e| e.to_string())
}

/// Search ledger entries by user ID or GPG fingerprint.
#[tauri::command]
pub fn search_ledger(
    query: String,
    state: State<'_, AppState>,
) -> std::result::Result<Vec<LedgerEntry>, String> {
    let db = state.db.lock().unwrap();
    distributor::search_by_user(&db, &query).map_err(|e| e.to_string())
}
