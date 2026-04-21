use serde::Serialize;
use tauri::State;

use crate::AppState;
use crate::crypto::cover_crypt_ops;
use crate::storage::schema::CF_MASTER_KEYS;
use super::file_opener;

/// Size threshold for inline preview (10 MiB).
const INLINE_PREVIEW_MAX: usize = 10 << 20;

/// Basic file info returned for display, with optional inline preview.
#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub size: u64,
    pub name: String,
    pub mime: String,
    pub category: String,
    /// base64 data for inline preview (only for renderable files < 10 MiB).
    pub preview_base64: Option<String>,
    /// Pre-built data URI for inline preview.
    pub preview_data_url: Option<String>,
}

/// Return file size and name for a given path.
/// For small renderable files (< 10 MiB), also returns preview data.
#[tauri::command]
pub fn get_file_info(path: String) -> std::result::Result<FileInfo, String> {
    use base64::Engine;

    let meta = std::fs::metadata(&path)
        .map_err(|e| format!("Cannot read file: {e}"))?;
    let name = std::path::Path::new(&path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let size = meta.len();

    // For small files, read content and detect type for preview
    if size <= INLINE_PREVIEW_MAX as u64 {
        if let Ok(data) = std::fs::read(&path) {
            let ft = file_opener::detect_file_type(&data);
            let (mime, category) = match &ft {
                Some(f) => {
                    let cat = file_opener::classify_mime(&f.mime);
                    (f.mime.clone(), format!("{:?}", cat))
                }
                None => {
                    if std::str::from_utf8(&data).is_ok() {
                        ("text/plain".into(), "Text".into())
                    } else {
                        ("application/octet-stream".into(), "Binary".into())
                    }
                }
            };

            let is_previewable = !matches!(category.as_str(), "Binary");
            if is_previewable {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                let data_url = format!("data:{};base64,{}", mime, b64);
                return Ok(FileInfo {
                    size, name, mime, category,
                    preview_base64: Some(b64),
                    preview_data_url: Some(data_url),
                });
            }

            return Ok(FileInfo {
                size, name, mime, category,
                preview_base64: None,
                preview_data_url: None,
            });
        }
    }

    Ok(FileInfo {
        size, name,
        mime: "application/octet-stream".into(),
        category: "Binary".into(),
        preview_base64: None,
        preview_data_url: None,
    })
}

/// Result of file encryption.
#[derive(Debug, Clone, Serialize)]
pub struct EncryptFileResult {
    pub input_size: u64,
    pub output_size: u64,
    pub output_path: String,
}

/// Result of file decryption.
#[derive(Debug, Clone, Serialize)]
pub struct DecryptFileResult {
    pub size: usize,
    pub mime: String,
    pub extension: String,
    pub temp_path: String,
    pub category: String,
    pub preview_base64: Option<String>,
    pub preview_data_url: Option<String>,
}

/// Encrypt a file on disk.
///
/// Reads plaintext from `input_path`, encrypts it, writes ciphertext to a
/// temp file.  Returns the temp path and sizes.
#[tauri::command]
pub fn encrypt_file(
    input_path: String,
    policy: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    use std::io::BufWriter;

    let plaintext = std::fs::read(&input_path)
        .map_err(|e| format!("Failed to read input file: {e}"))?;
    let input_size = plaintext.len() as u64;

    let db = state.db.lock().unwrap();
    let mpk_bytes = db
        .get_cf(CF_MASTER_KEYS, b"mpk")
        .map_err(|e| e.to_string())?
        .ok_or("Master key not initialized")?;
    drop(db);

    let broadcast_ct = cover_crypt_ops::encrypt(&mpk_bytes, &policy, &plaintext)
        .map_err(|e| e.to_string())?;

    // Derive output filename from input
    let input_name = std::path::Path::new(&input_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "encrypted".into());

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", input_name));

    // Stream directly to disk
    let file = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {e}"))?;
    let writer = BufWriter::new(file);
    bincode::serialize_into(writer, &broadcast_ct)
        .map_err(|e| format!("Failed to write ciphertext: {e}"))?;

    let output_size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    // Register for cleanup
    state.temp_files.lock().unwrap().push(output_path.clone());

    tracing::info!(
        input_path = %input_path,
        output_path = %output_path.display(),
        input_size,
        output_size,
        "File encrypted"
    );

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}

/// Decrypt a file on disk.
///
/// Reads ciphertext from `input_path`, decrypts it, writes plaintext to a
/// temp file.  For files < 10 MiB, also returns base64 data for inline preview.
#[tauri::command]
pub fn decrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    use base64::Engine;
    use crate::storage::models::ReceiverKey;
    use crate::storage::schema::CF_RECEIVER;

    // 1. Load active receiver key
    let db = state.db.lock().unwrap();
    let active_id = db
        .get_cf(CF_RECEIVER, b"__active__")
        .map_err(|e| e.to_string())?
        .ok_or("No decryption key loaded. Go to the Receiver tab and import a key first.")?;
    let rk_data = db
        .get_cf(CF_RECEIVER, &active_id)
        .map_err(|e| e.to_string())?
        .ok_or("Active receiver key not found in database")?;
    let rk: ReceiverKey = bincode::deserialize(&rk_data).map_err(|e| e.to_string())?;
    drop(db);

    // 2. Read ciphertext from disk
    let ct_bytes = std::fs::read(&input_path)
        .map_err(|e| format!("Failed to read ciphertext file: {e}"))?;

    let broadcast_ct: cover_crypt_ops::BroadcastCiphertext =
        bincode::deserialize(&ct_bytes)
            .map_err(|e| format!("Invalid ciphertext file: {e}"))?;

    // 3. Decrypt
    let plaintext = cover_crypt_ops::decrypt(&rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "File decryption failed");
            e.to_string()
        })?;

    // 4. Detect file type
    let ft = file_opener::detect_file_type(&plaintext);
    let (mime, extension, category) = match &ft {
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

    // 5. Write to temp file
    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let filename = format!("dec_{}.{}", uuid::Uuid::new_v4(), extension);
    let temp_path = dir.join(&filename);
    std::fs::write(&temp_path, &plaintext)
        .map_err(|e| format!("Failed to write temp file: {e}"))?;

    // Register for cleanup
    state.temp_files.lock().unwrap().push(temp_path.clone());

    // 6. Inline preview for small files
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
        mime,
        extension,
        temp_path: temp_path.display().to_string(),
        category,
        preview_base64,
        preview_data_url,
    })
}

/// Copy a temp file to a user-chosen destination.
/// Works for both encrypted and decrypted temp files.
#[tauri::command]
pub fn save_temp_file(
    temp_path: String,
    dest_path: String,
) -> std::result::Result<(), String> {
    std::fs::copy(&temp_path, &dest_path)
        .map_err(|e| format!("Failed to save file: {e}"))?;
    tracing::info!(src = %temp_path, dest = %dest_path, "Temp file saved");
    Ok(())
}
