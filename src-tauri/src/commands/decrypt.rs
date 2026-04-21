use tauri::State;

use crate::AppState;
use crate::crypto::broadcast::{self, BroadcastCiphertext};
use super::file_opener;
use crate::storage::models::DecryptResult;

/// Decrypt a ciphertext (base64-encoded bincode).
///
/// Uses the active receiver key's BGW index for decryption.
#[tauri::command]
pub fn decrypt_content(
    ciphertext_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    // 1. Load active receiver key
    let db = state.db.lock().unwrap();
    let rk = load_active_rk(&db)?;
    drop(db);

    // 2. Decode ciphertext
    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        bincode::deserialize(&ct_bytes).map_err(|e| format!("Invalid ciphertext: {e}"))?;

    // 3. Decrypt
    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = broadcast::decrypt(bgw, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "Decryption failed");
            e.to_string()
        })?;

    // 4. Detect file type and build Inline render
    let ft = file_opener::detect_file_type(&plaintext);
    let (mime, extension, _category) = match &ft {
        Some(f) => {
            let cat = file_opener::classify_mime(&f.mime);
            (f.mime.clone(), f.extension.clone(), format!("{:?}", cat))
        }
        None => {
            if std::str::from_utf8(&plaintext).is_ok() {
                ("text/plain".into(), "txt".into(), "Text".into())
            } else {
                ("application/octet-stream".into(), "bin".into(), "Binary".into())
            }
        }
    };

    let b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);
    let render = file_opener::RenderAction::Inline {
        data_base64: b64.clone(),
        data_url: format!("data:{};base64,{}", mime, b64),
        mime: mime.clone(),
        extension,
        category: file_opener::classify_mime(&mime),
    };

    Ok(DecryptResult {
        success: true,
        size_bytes: plaintext.len(),
        render,
        message: "Decryption successful".into(),
    })
}

/// Decrypt and open with system default application.
#[tauri::command]
pub fn decrypt_and_open(
    ciphertext_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    let db = state.db.lock().unwrap();
    let rk = load_active_rk(&db)?;
    drop(db);

    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        bincode::deserialize(&ct_bytes).map_err(|e| format!("Invalid ciphertext: {e}"))?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = broadcast::decrypt(bgw, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| e.to_string())?;

    let ft = file_opener::detect_file_type(&plaintext);
    let ext = ft.as_ref().map(|f| f.extension.as_str()).unwrap_or("bin");
    let mime = ft.as_ref().map(|f| f.mime.clone()).unwrap_or_else(|| "application/octet-stream".into());

    let path = file_opener::write_temp_and_open(&plaintext, ext).map_err(|e| e.to_string())?;
    state.temp_files.lock().unwrap().push(path.clone());

    let render = file_opener::RenderAction::External {
        mime,
        extension: ext.to_string(),
        temp_path: path.display().to_string(),
    };

    Ok(DecryptResult {
        success: true,
        size_bytes: plaintext.len(),
        render,
        message: "Opened with system default application".into(),
    })
}

/// Import a GPG-encrypted receiver key (contains BGW private key + index).
#[tauri::command]
pub fn import_receiver_key(
    encrypted_bytes: Vec<u8>,
    armored_secret_key: String,
    passphrase: String,
    label: String,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    use crate::crypto::gpg_ops;
    use crate::storage::models::{ReceiverKey, UserKeyRecord};
    use crate::storage::schema::CF_RECEIVER;

    let sk = gpg_ops::parse_secret_key(&armored_secret_key).map_err(|e| e.to_string())?;
    let decrypted = gpg_ops::decrypt_with_secret_key(&encrypted_bytes, &sk, &passphrase)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decrypt receiver key");
            e.to_string()
        })?;

    // Deserialize the key bundle to extract bgw_index + key_data
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
    };

    let db = state.db.lock().unwrap();
    let data = bincode::serialize(&rk).map_err(|e| e.to_string())?;
    db.put_cf(CF_RECEIVER, id.as_bytes(), &data).map_err(|e| e.to_string())?;
    db.put_cf(CF_RECEIVER, b"__active__", id.as_bytes()).map_err(|e| e.to_string())?;

    Ok(id)
}

/// List all saved receiver keys.
#[tauri::command]
pub fn list_receiver_keys(
    state: State<'_, AppState>,
) -> std::result::Result<Vec<ReceiverKeyInfo>, String> {
    use crate::storage::models::ReceiverKey;
    use crate::storage::schema::CF_RECEIVER;

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
pub fn set_active_receiver_key(
    key_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    use crate::storage::schema::CF_RECEIVER;
    let db = state.db.lock().unwrap();
    db.get_cf(CF_RECEIVER, key_id.as_bytes())
        .map_err(|e| e.to_string())?.ok_or("Key not found")?;
    db.put_cf(CF_RECEIVER, b"__active__", key_id.as_bytes()).map_err(|e| e.to_string())
}

/// Delete a receiver key.
#[tauri::command]
pub fn delete_receiver_key(
    key_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    use crate::storage::schema::CF_RECEIVER;
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
pub fn load_active_receiver_key(
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    use crate::storage::models::ReceiverKey;
    use crate::storage::schema::CF_RECEIVER;

    let db = state.db.lock().unwrap();
    let active_id = match db.get_cf(CF_RECEIVER, b"__active__").map_err(|e| e.to_string())? {
        Some(b) => String::from_utf8_lossy(&b).to_string(),
        None => return Ok(String::new()),
    };
    match db.get_cf(CF_RECEIVER, active_id.as_bytes()).map_err(|e| e.to_string())? {
        Some(data) => {
            let rk: ReceiverKey = bincode::deserialize(&data).map_err(|e| e.to_string())?;
            // Return the BGW index as a string (frontend uses this to check if key is loaded)
            Ok(rk.bgw_index.to_string())
        }
        None => Ok(String::new()),
    }
}

#[derive(serde::Serialize)]
pub struct ReceiverKeyInfo {
    pub id: String,
    pub label: String,
    pub created_at: String,
    pub active: bool,
    pub bgw_index: u32,
}

/// Helper: load active receiver key from DB.
fn load_active_rk(db: &crate::storage::db::Database) -> std::result::Result<crate::storage::models::ReceiverKey, String> {
    use crate::storage::models::ReceiverKey;
    use crate::storage::schema::CF_RECEIVER;

    let active_id = db.get_cf(CF_RECEIVER, b"__active__")
        .map_err(|e| e.to_string())?
        .ok_or("No decryption key loaded. Go to the Receiver tab and import a key first.")?;
    let rk_data = db.get_cf(CF_RECEIVER, &active_id)
        .map_err(|e| e.to_string())?
        .ok_or("Active receiver key not found")?;
    bincode::deserialize::<ReceiverKey>(&rk_data).map_err(|e| e.to_string())
}
