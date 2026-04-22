//! System initialization.
//!
//! With the namespace model, BGW systems are created per-namespace via
//! `create_namespace`. This command now just performs startup checks and
//! restores the active namespace if one was previously set.

use tauri::State;

use crate::AppState;
use crate::storage::schema::{CF_NAMESPACES, CF_CONFIG};

/// Perform startup initialization.
///
/// Restores the previously active namespace (if any). Returns `true` if
/// at least one namespace exists.
#[tauri::command]
pub fn ensure_initialized(
    state: State<'_, AppState>,
) -> std::result::Result<bool, String> {
    let db = state.db.lock().unwrap();

    // Restore active namespace from config
    if let Some(ns_id_bytes) = db.get_cf(CF_CONFIG, b"active_namespace")
        .map_err(|e| e.to_string())?
    {
        let ns_id = String::from_utf8_lossy(&ns_id_bytes).to_string();
        // Verify namespace still exists
        if db.get_cf(CF_NAMESPACES, ns_id.as_bytes())
            .map_err(|e| e.to_string())?
            .is_some()
        {
            *state.active_namespace.lock().unwrap() = Some(ns_id.clone());
            // Eagerly load BGW system for active namespace
            drop(db);
            super::namespace::load_bgw_system(&ns_id, &state)?;
            return Ok(true);
        }
    }

    // Check if any namespaces exist
    let entries = db.iter_cf(CF_NAMESPACES).map_err(|e| e.to_string())?;
    if let Some((k, _v)) = entries.first() {
        let ns_id = String::from_utf8_lossy(k).to_string();
        *state.active_namespace.lock().unwrap() = Some(ns_id.clone());
        db.put_cf(CF_CONFIG, b"active_namespace", ns_id.as_bytes())
            .map_err(|e| e.to_string())?;
        drop(db);
        super::namespace::load_bgw_system(&ns_id, &state)?;
        return Ok(true);
    }

    Ok(false)
}
