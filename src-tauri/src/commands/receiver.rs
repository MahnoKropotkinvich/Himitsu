//! Receiver-side key management: import, list, activate, delete.

use tauri::State;

use crate::AppState;
use crate::crypto::gpg;
use crate::storage::models::{ReceiverKey, ReceiverKeyInfo, UserKeyRecord};
use crate::storage::schema::CF_RECEIVER;

/// Import a GPG-encrypted receiver key (contains BGW private key + index + PK).
#[tauri::command]
pub fn import_key(
    encrypted_bytes: Vec<u8>,
    armored_secret_key: String,
    passphrase: String,
    label: String,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    let sk = gpg::parse_secret_key(&armored_secret_key).map_err(|e| e.to_string())?;
    let decrypted = gpg::decrypt_with_secret_key(&encrypted_bytes, &sk, &passphrase)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decrypt receiver key");
            e.to_string()
        })?;

    let bundle: UserKeyRecord = bincode::deserialize(&decrypted)
        .map_err(|e| format!("Invalid key format: {e}"))?;

    tracing::info!(bgw_index = bundle.bgw_index, "Receiver key imported");

    let id = uuid::Uuid::new_v4().to_string();
    let rk = ReceiverKey {
        id: id.clone(),
        label,
        created_at: chrono::Utc::now(),
        bgw_index: bundle.bgw_index,
        usk_bytes: bundle.key_data,
        pk_bytes: bundle.pk_data,
    };

    let db = state.db.lock().unwrap();
    let data = bincode::serialize(&rk).map_err(|e| e.to_string())?;
    db.put_cf(CF_RECEIVER, id.as_bytes(), &data).map_err(|e| e.to_string())?;
    db.put_cf(CF_RECEIVER, b"__active__", id.as_bytes()).map_err(|e| e.to_string())?;

    Ok(id)
}

/// List all saved receiver keys.
#[tauri::command]
pub fn list_keys(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<ReceiverKeyInfo>, String> {
    let db = state.db.lock().unwrap();
    let active_id = db.get_cf(CF_RECEIVER, b"__active__")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    let entries = db.iter_cf(CF_RECEIVER).map_err(|e| e.to_string())?;
    let mut keys = Vec::new();
    for (k, v) in entries {
        let key_str = String::from_utf8_lossy(&k);
        if key_str == "__active__" { continue; }
        if let Ok(rk) = bincode::deserialize::<ReceiverKey>(&v) {
            keys.push(ReceiverKeyInfo {
                id: rk.id.clone(),
                label: rk.label,
                created_at: rk.created_at.to_rfc3339(),
                active: rk.id == active_id,
                bgw_index: rk.bgw_index,
            });
        }
    }
    Ok(keys)
}

/// Set active receiver key.
#[tauri::command]
pub fn set_active_key(
    key_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();
    db.get_cf(CF_RECEIVER, key_id.as_bytes())
        .map_err(|e| e.to_string())?.ok_or("Key not found")?;
    db.put_cf(CF_RECEIVER, b"__active__", key_id.as_bytes()).map_err(|e| e.to_string())
}

/// Delete a receiver key.
#[tauri::command]
pub fn delete_key(
    key_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    let db = state.db.lock().unwrap();
    let active_id = db.get_cf(CF_RECEIVER, b"__active__")
        .map_err(|e| e.to_string())?
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    db.delete_cf(CF_RECEIVER, key_id.as_bytes()).map_err(|e| e.to_string())?;
    if active_id == key_id {
        db.delete_cf(CF_RECEIVER, b"__active__").map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Load active receiver key's BGW index (for frontend status).
#[tauri::command]
pub fn get_active_key(
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    let db = state.db.lock().unwrap();
    let active_id = match db.get_cf(CF_RECEIVER, b"__active__").map_err(|e| e.to_string())? {
        Some(b) => String::from_utf8_lossy(&b).to_string(),
        None => return Ok(String::new()),
    };
    match db.get_cf(CF_RECEIVER, active_id.as_bytes()).map_err(|e| e.to_string())? {
        Some(data) => {
            let rk: ReceiverKey = bincode::deserialize(&data).map_err(|e| e.to_string())?;
            Ok(rk.bgw_index.to_string())
        }
        None => Ok(String::new()),
    }
}

/// Helper: load active receiver key from DB (used by decrypt commands).
pub fn load_active(db: &crate::storage::db::Database) -> std::result::Result<ReceiverKey, String> {
    let active_id = db.get_cf(CF_RECEIVER, b"__active__")
        .map_err(|e| e.to_string())?
        .ok_or("No decryption key loaded. Go to the Receiver tab and import a key first.")?;
    let rk_data = db.get_cf(CF_RECEIVER, &active_id)
        .map_err(|e| e.to_string())?
        .ok_or("Active receiver key not found")?;
    bincode::deserialize::<ReceiverKey>(&rk_data).map_err(|e| e.to_string())
}
