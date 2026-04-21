//! BGW broadcast system initialization.

use tauri::State;

use crate::AppState;
use crate::crypto::bgw;
use crate::storage::schema::CF_BGW_SYSTEM;

/// Ensure the BGW broadcast system is initialized.
///
/// Loads from DB on restart, or generates + persists on first launch.
/// Returns `true` if a new system was generated.
#[tauri::command]
pub fn ensure_initialized(
    state: State<'_, AppState>,
) -> std::result::Result<bool, String> {
    let mut bgw_guard = state.bgw.lock().unwrap();
    if bgw_guard.is_some() {
        return Ok(false);
    }

    let db = state.db.lock().unwrap();

    if let Some(data) = db.get_cf(CF_BGW_SYSTEM, b"bgw_system").map_err(|e| e.to_string())? {
        tracing::info!("Loading BGW system from database");
        let sys = bgw::BgwSystem::load(&data).map_err(|e| e.to_string())?;
        *bgw_guard = Some(sys);
        return Ok(false);
    }

    tracing::info!("First launch: generating BGW broadcast system (N={})", bgw::MAX_USERS);
    let sys = bgw::BgwSystem::generate().map_err(|e| e.to_string())?;
    let serialized = sys.serialize().map_err(|e| e.to_string())?;
    db.put_cf(CF_BGW_SYSTEM, b"bgw_system", &serialized).map_err(|e| e.to_string())?;
    tracing::info!(bytes = serialized.len(), "BGW system persisted to database");
    *bgw_guard = Some(sys);
    Ok(true)
}
