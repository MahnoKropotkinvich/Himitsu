//! Decryption commands: file, folder, and inline content decryption.

use tauri::State;

use crate::AppState;
use crate::crypto::bgw::{self, BroadcastCiphertext};
use crate::storage::models::{DecryptResult, DecryptFileResult};
use crate::util::file_type;

/// Decrypt a ciphertext (base64-encoded bincode).
///
/// Uses the active receiver key's BGW private key for decryption.
#[tauri::command]
pub fn decrypt_content(
    ciphertext_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    let db = state.db.lock().unwrap();
    let rk = super::keys::load_active_rk(&db)?;
    drop(db);

    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        bincode::deserialize(&ct_bytes).map_err(|e| format!("Invalid ciphertext: {e}"))?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = bgw::decrypt(bgw_sys, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "Decryption failed");
            e.to_string()
        })?;

    let ft = file_type::detect_file_type(&plaintext);
    let (mime, extension, _category) = match &ft {
        Some(f) => {
            let cat = file_type::classify_mime(&f.mime);
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
    let render = crate::storage::models::RenderAction::Inline {
        data_base64: b64.clone(),
        data_url: format!("data:{};base64,{}", mime, b64),
        mime: mime.clone(),
        extension,
        category: file_type::classify_mime(&mime),
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
    let rk = super::keys::load_active_rk(&db)?;
    drop(db);

    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        bincode::deserialize(&ct_bytes).map_err(|e| format!("Invalid ciphertext: {e}"))?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = bgw::decrypt(bgw_sys, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| e.to_string())?;

    let ft = file_type::detect_file_type(&plaintext);
    let ext = ft.as_ref().map(|f| f.extension.as_str()).unwrap_or("bin");
    let mime = ft.as_ref().map(|f| f.mime.clone()).unwrap_or_else(|| "application/octet-stream".into());

    let path = file_type::write_temp_and_open(&plaintext, ext).map_err(|e| e.to_string())?;
    state.temp_files.lock().unwrap().push(path.clone());

    let render = crate::storage::models::RenderAction::External {
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

/// Decrypt a file on disk.
///
/// For files < 10 MiB, also returns base64 data for inline preview.
#[tauri::command]
pub fn decrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    use base64::Engine;

    let db = state.db.lock().unwrap();
    let rk = super::keys::load_active_rk(&db)?;
    drop(db);

    let ct_bytes = std::fs::read(&input_path)
        .map_err(|e| format!("Failed to read ciphertext file: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        bincode::deserialize(&ct_bytes)
            .map_err(|e| format!("Invalid ciphertext file: {e}"))?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = bgw::decrypt(bgw_sys, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "File decryption failed");
            e.to_string()
        })?;

    // Check if decrypted content is a tar archive (encrypted folder)
    let is_tar = plaintext.len() > 262 && &plaintext[257..262] == b"ustar";

    if is_tar {
        let dir = std::env::temp_dir().join("himitsu");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let out_dir = dir.join(format!("dir_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;

        let cursor = std::io::Cursor::new(&plaintext);
        let mut archive = tar::Archive::new(cursor);
        archive.unpack(&out_dir)
            .map_err(|e| format!("Failed to untar: {e}"))?;

        tracing::info!(
            input_path = %input_path,
            output_dir = %out_dir.display(),
            tar_size = plaintext.len(),
            "Decrypted folder extracted"
        );

        return Ok(DecryptFileResult {
            size: plaintext.len(),
            mime: "inode/directory".into(),
            extension: String::new(),
            temp_path: out_dir.display().to_string(),
            category: "Folder".into(),
            preview_base64: None,
            preview_data_url: None,
        });
    }

    // Detect file type (regular file)
    let ft = file_type::detect_file_type(&plaintext);
    let (mime, extension, category) = match &ft {
        Some(f) => {
            let cat = file_type::classify_mime(&f.mime);
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

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let filename = format!("dec_{}.{}", uuid::Uuid::new_v4(), extension);
    let temp_path = dir.join(&filename);
    std::fs::write(&temp_path, &plaintext)
        .map_err(|e| format!("Failed to write temp file: {e}"))?;

    state.temp_files.lock().unwrap().push(temp_path.clone());

    /// Size threshold for inline preview (10 MiB).
    const INLINE_PREVIEW_MAX: usize = 10 << 20;

    let (preview_base64, preview_data_url) = if plaintext.len() <= INLINE_PREVIEW_MAX {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&plaintext);
        let data_url = format!("data:{};base64,{}", mime, b64);
        (Some(b64), Some(data_url))
    } else {
        (None, None)
    };

    tracing::info!(
        input_path = %input_path,
        plaintext_size = plaintext.len(),
        mime = %mime,
        "File decrypted"
    );

    Ok(DecryptFileResult {
        size: plaintext.len(),
        mime, extension,
        temp_path: temp_path.display().to_string(),
        category,
        preview_base64, preview_data_url,
    })
}

/// Decrypt a .himitsu file that contains a tar archive (folder).
#[tauri::command]
pub fn decrypt_to_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    let db = state.db.lock().unwrap();
    let rk = super::keys::load_active_rk(&db)?;
    drop(db);

    let ct_bytes = std::fs::read(&input_path)
        .map_err(|e| format!("Failed to read ciphertext file: {e}"))?;
    let broadcast_ct: BroadcastCiphertext =
        bincode::deserialize(&ct_bytes)
            .map_err(|e| format!("Invalid ciphertext file: {e}"))?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = bgw::decrypt(bgw_sys, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "Folder decryption failed");
            e.to_string()
        })?;

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out_dir = dir.join(format!("dir_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;

    let cursor = std::io::Cursor::new(&plaintext);
    let mut archive = tar::Archive::new(cursor);
    archive.unpack(&out_dir)
        .map_err(|e| format!("Failed to untar: {e}"))?;

    tracing::info!(
        input_path = %input_path,
        output_dir = %out_dir.display(),
        plaintext_size = plaintext.len(),
        "Folder decrypted and extracted"
    );

    Ok(DecryptFileResult {
        size: plaintext.len(),
        mime: "inode/directory".into(),
        extension: String::new(),
        temp_path: out_dir.display().to_string(),
        category: "Folder".into(),
        preview_base64: None,
        preview_data_url: None,
    })
}
