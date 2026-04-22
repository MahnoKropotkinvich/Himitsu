//! Namespace management: create, list, select, and inspect namespaces.
//!
//! Each namespace owns a separate BGW system (N=1000 slots). Encryption
//! always targets all 1000 slots so that users assigned later can decrypt
//! earlier content.

use tauri::State;

use crate::AppState;
use crate::crypto::bgw::{self, BgwSystem};
use crate::storage::models::{KeySlot, Namespace, NamespaceInfo, SlotState};
use crate::storage::schema::*;

/// Create a new namespace with a fresh BGW system (1000 slots).
///
/// All slots start as `Available`. Returns the namespace ID.
#[tauri::command]
pub fn create_namespace(
    name: String,
    state: State<'_, AppState>,
) -> std::result::Result<NamespaceInfo, String> {
    let ns_id = uuid::Uuid::new_v4().to_string();

    tracing::info!(namespace_id = %ns_id, name = %name, "Creating namespace");

    // Generate BGW system
    let bgw_sys = BgwSystem::generate().map_err(|e| e.to_string())?;
    let serialized = bgw_sys.serialize().map_err(|e| e.to_string())?;

    let ns = Namespace {
        id: ns_id.clone(),
        name: name.clone(),
        created_at: chrono::Utc::now(),
    };

    let db = state.db.lock().unwrap();

    // Store namespace metadata
    let ns_bytes = bincode::serialize(&ns).map_err(|e| e.to_string())?;
    db.put_cf(CF_NAMESPACES, ns_id.as_bytes(), &ns_bytes)
        .map_err(|e| e.to_string())?;

    // Store BGW system
    db.put_cf(CF_BGW_SYSTEM, ns_id.as_bytes(), &serialized)
        .map_err(|e| e.to_string())?;

    // Initialize all 1000 key slots as Available
    for i in 0..bgw::MAX_USERS as u32 {
        let slot = KeySlot {
            namespace_id: ns_id.clone(),
            index: i,
            state: SlotState::Available,
            user_id: None,
            assigned_at: None,
        };
        let slot_key = format!("{}:{:04}", ns_id, i);
        let slot_bytes = bincode::serialize(&slot).map_err(|e| e.to_string())?;
        db.put_cf(CF_KEY_SLOTS, slot_key.as_bytes(), &slot_bytes)
            .map_err(|e| e.to_string())?;
    }

    tracing::info!(
        namespace_id = %ns_id,
        bgw_bytes = serialized.len(),
        "Namespace created with {} slots",
        bgw::MAX_USERS
    );

    // Cache BGW system in memory
    state.bgw.lock().unwrap().insert(ns_id.clone(), bgw_sys);

    // Set as active if no active namespace exists
    {
        let mut active = state.active_namespace.lock().unwrap();
        if active.is_none() {
            *active = Some(ns_id.clone());
        }
    }

    Ok(NamespaceInfo {
        id: ns_id,
        name,
        created_at: ns.created_at.to_rfc3339(),
        total_slots: bgw::MAX_USERS as u32,
        available: bgw::MAX_USERS as u32,
        assigned: 0,
        revoked: 0,
        deleted: 0,
    })
}

/// List all namespaces with slot statistics.
#[tauri::command]
pub fn list_namespaces(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<NamespaceInfo>, String> {
    let db = state.db.lock().unwrap();
    let entries = db.iter_cf(CF_NAMESPACES).map_err(|e| e.to_string())?;

    let mut infos = Vec::new();
    for (_k, v) in entries {
        let ns: Namespace = match bincode::deserialize(&v) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let info = build_namespace_info(&db, &ns)?;
        infos.push(info);
    }

    Ok(infos)
}

/// Get the currently active namespace ID.
#[tauri::command]
pub fn get_active_namespace(
    state: State<'_, AppState>,
) -> std::result::Result<Option<String>, String> {
    Ok(state.active_namespace.lock().unwrap().clone())
}

/// Set the active namespace.
#[tauri::command]
pub fn set_active_namespace(
    namespace_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    // Verify namespace exists
    let db = state.db.lock().unwrap();
    db.get_cf(CF_NAMESPACES, namespace_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("Namespace not found")?;

    *state.active_namespace.lock().unwrap() = Some(namespace_id);
    Ok(())
}

/// Helper: compute slot statistics for a namespace.
fn build_namespace_info(
    db: &crate::storage::db::Database,
    ns: &Namespace,
) -> std::result::Result<NamespaceInfo, String> {
    let prefix = format!("{}:", ns.id);
    let slots = db.prefix_iter_cf(CF_KEY_SLOTS, prefix.as_bytes())
        .map_err(|e| e.to_string())?;

    let (mut available, mut assigned, mut revoked, mut deleted) = (0u32, 0, 0, 0);
    for (_k, v) in &slots {
        if let Ok(slot) = bincode::deserialize::<KeySlot>(v) {
            match slot.state {
                SlotState::Available => available += 1,
                SlotState::Assigned => assigned += 1,
                SlotState::Revoked => revoked += 1,
                SlotState::Deleted => deleted += 1,
            }
        }
    }

    Ok(NamespaceInfo {
        id: ns.id.clone(),
        name: ns.name.clone(),
        created_at: ns.created_at.to_rfc3339(),
        total_slots: bgw::MAX_USERS as u32,
        available,
        assigned,
        revoked,
        deleted,
    })
}

/// Helper: load or cache a BGW system for a namespace.
pub fn load_bgw_system(
    namespace_id: &str,
    state: &AppState,
) -> std::result::Result<(), String> {
    let mut bgw_map = state.bgw.lock().unwrap();
    if bgw_map.contains_key(namespace_id) {
        return Ok(());
    }

    let db = state.db.lock().unwrap();
    let data = db
        .get_cf(CF_BGW_SYSTEM, namespace_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or_else(|| format!("BGW system not found for namespace {namespace_id}"))?;

    let sys = BgwSystem::load(&data).map_err(|e| e.to_string())?;
    bgw_map.insert(namespace_id.to_string(), sys);

    tracing::info!(namespace_id, "BGW system loaded from DB");
    Ok(())
}

/// Helper: get the active namespace ID or error.
pub fn require_active_namespace(state: &AppState) -> std::result::Result<String, String> {
    state
        .active_namespace
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "No active namespace. Create or select a namespace first.".into())
}
