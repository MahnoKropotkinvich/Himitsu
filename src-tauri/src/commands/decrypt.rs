use tauri::State;

use crate::AppState;
use crate::crypto::cover_crypt_ops::{self, BroadcastCiphertext};
use super::file_opener;
use crate::storage::models::DecryptResult;

/// Decrypt a ciphertext.
///
/// Automatically detects the file type of the plaintext and decides
/// whether to return inline data (image/text/video/audio/PDF rendered
/// directly in the WebView) or to write a temp file and open it with
/// the system default application.
#[tauri::command]
pub fn decrypt_content(
    ciphertext_json_base64: String,
    user_secret_key_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    // 1. Decode inputs
    let ct_json = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_json_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        serde_json::from_slice(&ct_json).map_err(|e| format!("Invalid ciphertext JSON: {e}"))?;

    let usk_bytes = base64::engine::general_purpose::STANDARD
        .decode(&user_secret_key_base64)
        .map_err(|e| format!("Invalid user key base64: {e}"))?;

    // 2. CoverCrypt decrypt
    tracing::debug!(
        ct_len = broadcast_ct.ciphertext.len(),
        usk_len = usk_bytes.len(),
        policy = %broadcast_ct.policy,
        "Attempting CoverCrypt decryption"
    );
    let plaintext =
        cover_crypt_ops::decrypt(&usk_bytes, &broadcast_ct).map_err(|e| {
            tracing::error!(error = %e, "Decryption failed");
            e.to_string()
        })?;

    // 3. Detect file type
    let ft = file_opener::detect_file_type(&plaintext);
    tracing::info!(
        plaintext_len = plaintext.len(),
        mime = ft.as_ref().map(|f| f.mime.as_str()).unwrap_or("unknown"),
        "Decryption successful"
    );

    // 4. Decide render action
    let mut render = file_opener::decide_render_action(&plaintext, ft.as_ref());

    // 5. If External, write temp file and open it
    if let file_opener::RenderAction::External {
        ref extension,
        ref mut temp_path,
        ..
    } = render
    {
        let path = file_opener::write_temp_and_open(&plaintext, extension)
            .map_err(|e| e.to_string())?;
        *temp_path = path.display().to_string();
        // Register for cleanup on exit
        state
            .temp_files
            .lock()
            .unwrap()
            .push(path);
    }

    Ok(DecryptResult {
        success: true,
        size_bytes: plaintext.len(),
        render,
        message: "Decryption successful".into(),
    })
}

/// Decrypt and explicitly open with the system default application,
/// bypassing inline rendering even for types the WebView supports.
#[tauri::command]
pub fn decrypt_and_open(
    ciphertext_json_base64: String,
    user_secret_key_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    // 1. Decode
    let ct_json = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_json_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        serde_json::from_slice(&ct_json).map_err(|e| format!("Invalid ciphertext JSON: {e}"))?;

    let usk_bytes = base64::engine::general_purpose::STANDARD
        .decode(&user_secret_key_base64)
        .map_err(|e| format!("Invalid user key base64: {e}"))?;

    // 2. Decrypt
    let plaintext =
        cover_crypt_ops::decrypt(&usk_bytes, &broadcast_ct).map_err(|e| e.to_string())?;

    // 3. Detect type, always open externally
    let ft = file_opener::detect_file_type(&plaintext);
    let ext = ft.as_ref().map(|f| f.extension.as_str()).unwrap_or("bin");
    let mime = ft
        .as_ref()
        .map(|f| f.mime.clone())
        .unwrap_or_else(|| "application/octet-stream".into());

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

/// Decrypt a GPG-encrypted user key blob, save it as a named receiver key
/// in the database, and set it as the active key.  Returns the key id.
#[tauri::command]
pub fn import_receiver_key(
    encrypted_bytes: Vec<u8>,
    armored_secret_key: String,
    passphrase: String,
    label: String,
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    use crate::crypto::gpg_ops;
    use crate::storage::models::ReceiverKey;
    use crate::storage::schema::CF_RECEIVER;

    tracing::info!(
        label = %label,
        encrypted_size = encrypted_bytes.len(),
        "Importing receiver key"
    );

    let sk = gpg_ops::parse_secret_key(&armored_secret_key)
        .map_err(|e| e.to_string())?;
    let decrypted = gpg_ops::decrypt_with_secret_key(&encrypted_bytes, &sk, &passphrase)
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to decrypt receiver key");
            e.to_string()
        })?;

    tracing::info!(usk_bytes = decrypted.len(), "Receiver key decrypted successfully");

    let id = uuid::Uuid::new_v4().to_string();
    let rk = ReceiverKey {
        id: id.clone(),
        label,
        created_at: chrono::Utc::now(),
        usk_bytes: decrypted,
    };

    let db = state.db.lock().unwrap();
    let data = bincode::serialize(&rk).map_err(|e| e.to_string())?;
    db.put_cf(CF_RECEIVER, id.as_bytes(), &data)
        .map_err(|e| e.to_string())?;
    // Set as active
    db.put_cf(CF_RECEIVER, b"__active__", id.as_bytes())
        .map_err(|e| e.to_string())?;

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
            });
        }
    }
    Ok(keys)
}

/// Set a specific receiver key as the active decryption key.
#[tauri::command]
pub fn set_active_receiver_key(
    key_id: String,
    state: State<'_, AppState>,
) -> std::result::Result<(), String> {
    use crate::storage::schema::CF_RECEIVER;
    let db = state.db.lock().unwrap();
    // Verify the key exists
    db.get_cf(CF_RECEIVER, key_id.as_bytes())
        .map_err(|e| e.to_string())?
        .ok_or("Key not found")?;
    db.put_cf(CF_RECEIVER, b"__active__", key_id.as_bytes())
        .map_err(|e| e.to_string())
}

/// Delete a receiver key. If it was the active key, clear the active pointer.
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
    db.delete_cf(CF_RECEIVER, key_id.as_bytes())
        .map_err(|e| e.to_string())?;
    if active_id == key_id {
        db.delete_cf(CF_RECEIVER, b"__active__")
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Load the ACTIVE receiver key's USK bytes as base64.
/// Returns empty string if none is set.
#[tauri::command]
pub fn load_active_receiver_key(
    state: State<'_, AppState>,
) -> std::result::Result<String, String> {
    use base64::Engine;
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
            Ok(base64::engine::general_purpose::STANDARD.encode(&rk.usk_bytes))
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
}
