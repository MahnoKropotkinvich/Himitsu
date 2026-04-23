//! Decryption commands: file, folder, and inline content decryption.

use std::io::BufReader;

use tauri::State;

use crate::AppState;
use crate::crypto::bgw;
use crate::storage::models::{DecryptResult, DecryptFileResult};
use crate::util::file_type;

/// Shared helper: open an HMT2 source and decrypt it.
///
/// The receiver's ReceiverKey contains the distributor's PK, so we don't
/// need the local namespace's BGW system. We only need a BgwSystem for the
/// pairing context (gps), which is the same across all namespaces.
fn decrypt_from_reader<R: std::io::Read>(
    input: &mut R,
    state: &State<'_, AppState>,
) -> std::result::Result<(Vec<u8>, bgw::BroadcastHeader), String> {
    let rk = {
        let db = state.db.lock().unwrap();
        super::receiver::load_active(&db)?
    };

    // We need any BgwSystem just for the pairing context (gps).
    // If none loaded, load or generate a temporary one.
    {
        let bgw_map = state.bgw.lock().unwrap();
        if bgw_map.is_empty() {
            drop(bgw_map);
            // Load the first namespace's BGW system, or generate a temp one
            let db = state.db.lock().unwrap();
            let entries = db.iter_cf(crate::storage::schema::CF_NAMESPACES)
                .map_err(|e| e.to_string())?;
            if let Some((k, _)) = entries.first() {
                let ns_id = String::from_utf8_lossy(k).to_string();
                drop(db);
                super::namespace::load_bgw_system(&ns_id, state)?;
            } else {
                // No namespaces exist — receiver-only mode.
                // Generate a temporary BGW system just for gps.
                drop(db);
                let tmp = bgw::BgwSystem::generate().map_err(|e| e.to_string())?;
                state.bgw.lock().unwrap().insert("__receiver_tmp__".into(), tmp);
            }
        }
    }

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.values().next()
        .ok_or("No BGW pairing context available")?;

    let (plaintext, hdr) = bgw::decrypt(bgw_sys, rk.bgw_index, &rk.usk_bytes, &rk.pk_bytes, input)
        .map_err(|e| {
            tracing::error!(error = %e, "Decryption failed");
            e.to_string()
        })?;

    Ok((plaintext, hdr))
}

/// Decrypt a ciphertext (base64-encoded HMT2 binary).
///
/// Uses the active receiver key's BGW private key for decryption.
#[tauri::command]
pub fn decrypt_content(
    ciphertext_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;

    let mut cursor = std::io::Cursor::new(&ct_bytes);
    let (plaintext, _hdr) = decrypt_from_reader(&mut cursor, &state)?;

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

/// Decrypt a file on disk (non-folder).
///
/// For files < 10 MiB, also returns base64 data for inline preview.
#[tauri::command]
pub fn decrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    use base64::Engine;

    let file = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to open ciphertext file: {e}"))?;
    let mut reader = BufReader::new(file);

    let (plaintext, hdr) = decrypt_from_reader(&mut reader, &state)?;
    let original_name = hdr.filename.clone();

    // If the header says this is a folder, handle tar extraction
    if hdr.is_folder {
        let dir = std::env::temp_dir().join("himitsu");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

        let cursor = std::io::Cursor::new(&plaintext);
        let mut archive = tar::Archive::new(cursor);
        archive.unpack(&dir)
            .map_err(|e| format!("Failed to untar: {e}"))?;

        // Find the top-level directory name from tar entries
        let cursor2 = std::io::Cursor::new(&plaintext);
        let mut archive2 = tar::Archive::new(cursor2);
        let top_dir = archive2.entries()
            .ok()
            .and_then(|mut entries| entries.next())
            .and_then(|e| e.ok())
            .and_then(|e| {
                let p = e.path().ok()?;
                let first = p.components().next()?;
                Some(first.as_os_str().to_string_lossy().to_string())
            })
            .unwrap_or_else(|| format!("dir_{}", uuid::Uuid::new_v4()));

        let out_dir = dir.join(&top_dir);

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
            original_name: original_name.clone(),
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

    // Use original filename for temp file — no UUID prefix
    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let filename = match &original_name {
        Some(name) => name.clone(),
        None => format!("dec_{}.{}", uuid::Uuid::new_v4(), extension),
    };
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
        original_name,
    })
}

/// Decrypt a .himitsu file that contains a tar archive (folder).
#[tauri::command]
pub fn decrypt_to_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    let file = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to open ciphertext file: {e}"))?;
    let mut reader = BufReader::new(file);

    let (plaintext, hdr) = decrypt_from_reader(&mut reader, &state)?;
    let original_name = hdr.filename.clone();

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let cursor = std::io::Cursor::new(&plaintext);
    let mut archive = tar::Archive::new(cursor);
    archive.unpack(&dir)
        .map_err(|e| format!("Failed to untar: {e}"))?;

    // Find the top-level directory name from tar entries
    let cursor2 = std::io::Cursor::new(&plaintext);
    let mut archive2 = tar::Archive::new(cursor2);
    let top_dir = archive2.entries()
        .ok()
        .and_then(|mut entries| entries.next())
        .and_then(|e| e.ok())
        .and_then(|e| {
            let p = e.path().ok()?;
            let first = p.components().next()?;
            Some(first.as_os_str().to_string_lossy().to_string())
        })
        .unwrap_or_else(|| format!("dir_{}", uuid::Uuid::new_v4()));

    let out_dir = dir.join(&top_dir);

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
        original_name,
    })
}
