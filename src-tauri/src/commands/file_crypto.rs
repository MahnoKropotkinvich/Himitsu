use serde::Serialize;
use tauri::State;

use crate::AppState;
use crate::crypto::broadcast;
use super::file_opener;
use super::broadcast as broadcast_cmds;

/// Size threshold for inline preview (10 MiB).
const INLINE_PREVIEW_MAX: usize = 10 << 20;

/// Basic file info returned for display, with optional inline preview.
#[derive(Debug, Clone, Serialize)]
pub struct FileInfo {
    pub size: u64,
    pub name: String,
    pub mime: String,
    pub category: String,
    pub is_dir: bool,
    /// base64 data for inline preview (only for renderable files < 10 MiB).
    pub preview_base64: Option<String>,
    /// Pre-built data URI for inline preview.
    pub preview_data_url: Option<String>,
}

/// Recursively compute total size of a directory.
fn dir_size(path: &std::path::Path) -> u64 {
    walkdir(path).iter().filter_map(|e| e.metadata().ok()).map(|m| m.len()).sum()
}
fn walkdir(path: &std::path::Path) -> Vec<std::fs::DirEntry> {
    let mut entries = Vec::new();
    if let Ok(rd) = std::fs::read_dir(path) {
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                entries.extend(walkdir(&p));
            } else {
                entries.push(entry);
            }
        }
    }
    entries
}

/// Return file/directory info for a given path.
/// For small renderable files (< 10 MiB), also returns preview data.
/// For directories, returns total size and "Folder" category.
#[tauri::command]
pub fn get_file_info(path: String) -> std::result::Result<FileInfo, String> {
    use base64::Engine;

    let p = std::path::Path::new(&path);
    let meta = std::fs::metadata(p)
        .map_err(|e| format!("Cannot read path: {e}"))?;
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    // Directory
    if meta.is_dir() {
        let size = dir_size(p);
        return Ok(FileInfo {
            size, name,
            mime: "inode/directory".into(),
            category: "Folder".into(),
            is_dir: true,
            preview_base64: None,
            preview_data_url: None,
        });
    }

    let size = meta.len();

    // For small files, read content and detect type for preview
    if size <= INLINE_PREVIEW_MAX as u64 {
        if let Ok(data) = std::fs::read(p) {
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
                    size, name, mime, category, is_dir: false,
                    preview_base64: Some(b64),
                    preview_data_url: Some(data_url),
                });
            }

            return Ok(FileInfo {
                size, name, mime, category, is_dir: false,
                preview_base64: None,
                preview_data_url: None,
            });
        }
    }

    Ok(FileInfo {
        size, name,
        mime: "application/octet-stream".into(),
        category: "Binary".into(),
        is_dir: false,
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

/// Encrypt a file on disk using BGW broadcast encryption.
///
/// Encrypts for all non-revoked users.
#[tauri::command]
pub fn encrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    use std::io::BufWriter;

    let plaintext = std::fs::read(&input_path)
        .map_err(|e| format!("Failed to read input file: {e}"))?;
    let input_size = plaintext.len() as u64;

    // Get active recipient indices
    let db = state.db.lock().unwrap();
    let recipients = broadcast_cmds::get_active_recipient_indices(&db)?;
    drop(db);

    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let broadcast_ct = broadcast::encrypt(bgw, &recipients, &plaintext)
        .map_err(|e| e.to_string())?;

    // Derive output filename
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

    let broadcast_ct: broadcast::BroadcastCiphertext =
        bincode::deserialize(&ct_bytes)
            .map_err(|e| format!("Invalid ciphertext file: {e}"))?;

    // 3. Decrypt using BGW
    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = broadcast::decrypt(bgw, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "File decryption failed");
            e.to_string()
        })?;

    // 4. Check if decrypted content is a tar archive (encrypted folder)
    //    tar magic: bytes 257..262 == "ustar"
    let is_tar = plaintext.len() > 262 && &plaintext[257..262] == b"ustar";

    if is_tar {
        // Extract to temp directory
        let dir = std::env::temp_dir().join("himitsu");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let out_dir = dir.join(format!("dir_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;

        let cursor = std::io::Cursor::new(&plaintext);
        let mut archive = tar::Archive::new(cursor);
        archive
            .unpack(&out_dir)
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

    // 5. Detect file type (regular file)
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
    let src = std::path::Path::new(&temp_path);
    let dst = std::path::Path::new(&dest_path);
    if src.is_dir() {
        // Copy directory recursively
        copy_dir_recursive(src, dst).map_err(|e| format!("Failed to save folder: {e}"))?;
    } else {
        std::fs::copy(src, dst)
            .map_err(|e| format!("Failed to save file: {e}"))?;
    }
    tracing::info!(src = %temp_path, dest = %dest_path, "Temp file saved");
    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let dest_child = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&entry.path(), &dest_child)?;
        } else {
            std::fs::copy(entry.path(), &dest_child)?;
        }
    }
    Ok(())
}

/// Encrypt a folder: tar → encrypt → single .himitsu temp file.
#[tauri::command]
pub fn encrypt_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    use std::io::BufWriter;

    let src = std::path::Path::new(&input_path);
    if !src.is_dir() {
        return Err("Path is not a directory".into());
    }

    // 1. Tar the directory into memory
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let dir_name = src.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".into());
        builder
            .append_dir_all(&dir_name, src)
            .map_err(|e| format!("Failed to tar directory: {e}"))?;
        builder
            .finish()
            .map_err(|e| format!("Failed to finalize tar: {e}"))?;
    }
    let input_size = tar_buf.len() as u64;

    tracing::debug!(
        tar_size = tar_buf.len(),
        "Folder tarred"
    );

    // 2. Encrypt the tar blob
    let db = state.db.lock().unwrap();
    let recipients = broadcast_cmds::get_active_recipient_indices(&db)?;
    drop(db);

    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let broadcast_ct = broadcast::encrypt(bgw, &recipients, &tar_buf)
        .map_err(|e| e.to_string())?;

    // 3. Write to temp file
    let folder_name = src.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "folder".into());

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", folder_name));

    let file = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {e}"))?;
    let writer = BufWriter::new(file);
    bincode::serialize_into(writer, &broadcast_ct)
        .map_err(|e| format!("Failed to write ciphertext: {e}"))?;

    let output_size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    state.temp_files.lock().unwrap().push(output_path.clone());

    tracing::info!(
        input_path = %input_path,
        output_path = %output_path.display(),
        input_size,
        output_size,
        "Folder encrypted"
    );

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}

/// Decrypt a .himitsu file that contains a tar archive (folder).
/// Extracts to a temp directory and returns the path.
#[tauri::command]
pub fn decrypt_to_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
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

    // 2. Read ciphertext
    let ct_bytes = std::fs::read(&input_path)
        .map_err(|e| format!("Failed to read ciphertext file: {e}"))?;
    let broadcast_ct: broadcast::BroadcastCiphertext =
        bincode::deserialize(&ct_bytes)
            .map_err(|e| format!("Invalid ciphertext file: {e}"))?;

    // 3. Decrypt
    let bgw_guard = state.bgw.lock().unwrap();
    let bgw = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let plaintext = broadcast::decrypt(bgw, rk.bgw_index, &rk.usk_bytes, &broadcast_ct)
        .map_err(|e| {
            tracing::error!(error = %e, "Folder decryption failed");
            e.to_string()
        })?;

    // 4. Untar to temp directory
    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let out_dir = dir.join(format!("dir_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&out_dir).map_err(|e| e.to_string())?;

    let cursor = std::io::Cursor::new(&plaintext);
    let mut archive = tar::Archive::new(cursor);
    archive
        .unpack(&out_dir)
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
