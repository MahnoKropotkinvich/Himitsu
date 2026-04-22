//! Decryption commands: file, folder, and inline content decryption.
//!
//! Streaming pipeline: File → ChunkDecryptor → zstd::Decoder → output
//! Memory usage: O(chunk_size) regardless of ciphertext size.

use std::io::{self, BufReader, BufWriter, Read, Write};
use tauri::State;

use crate::AppState;
use crate::crypto::bgw::{self, BroadcastHeader, ChunkDecryptor};
use crate::storage::models::{DecryptResult, DecryptFileResult};
use crate::util::file_type;

/// Open a .himitsu file, read its header, and derive the AES key.
///
/// Returns (header, plaintext_reader) where the reader yields decompressed
/// plaintext bytes via the streaming ChunkDecryptor → zstd pipeline.
fn open_himitsu<R: Read>(
    bgw_sys: &bgw::BgwSystem,
    user_index: u32,
    d_i_bytes: &[u8],
    mut reader: R,
) -> std::result::Result<(BroadcastHeader, zstd::Decoder<'static, BufReader<ChunkDecryptor<R>>>), String> {
    let hdr = bgw::read_file_header(&mut reader).map_err(|e| e.to_string())?;

    let aes_key = bgw_sys
        .decapsulate(user_index, d_i_bytes, &hdr.recipients, &hdr.header)
        .map_err(|e| {
            tracing::error!(error = %e, "BGW decapsulation failed");
            e.to_string()
        })?;

    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(&hdr.nonce[..8]);

    let chunk_dec = ChunkDecryptor::new(reader, aes_key, &hdr.nonce);
    let zstd_dec = zstd::Decoder::new(chunk_dec).map_err(|e| format!("zstd init: {e}"))?;

    Ok((hdr, zstd_dec))
}

/// Decrypt a ciphertext (base64-encoded streaming format).
///
/// Uses the active receiver key's BGW private key for decryption.
#[tauri::command]
pub fn decrypt_content(
    ciphertext_base64: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptResult, String> {
    use base64::Engine;

    let rk = {
        let db = state.db.lock().unwrap();
        super::keys::load_active_rk(&db)?
    };

    let ct_bytes = base64::engine::general_purpose::STANDARD
        .decode(&ciphertext_base64)
        .map_err(|e| format!("Invalid ciphertext base64: {e}"))?;

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let cursor = std::io::Cursor::new(ct_bytes);
    let (_hdr, mut plaintext_reader) =
        open_himitsu(bgw_sys, rk.bgw_index, &rk.usk_bytes, cursor)?;

    let mut plaintext = Vec::new();
    plaintext_reader
        .read_to_end(&mut plaintext)
        .map_err(|e| {
            tracing::error!(error = %e, "Decryption failed");
            format!("Decryption failed: {e}")
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

/// Decrypt a file on disk.
///
/// Streams ciphertext → ChunkDecryptor → zstd → temp file.
/// For files < 10 MiB, also returns base64 data for inline preview.
#[tauri::command]
pub fn decrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    use base64::Engine;

    let rk = {
        let db = state.db.lock().unwrap();
        super::keys::load_active_rk(&db)?
    };

    let file = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to open ciphertext file: {e}"))?;
    let reader = BufReader::new(file);

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let (hdr, mut plaintext_reader) =
        open_himitsu(bgw_sys, rk.bgw_index, &rk.usk_bytes, reader)?;

    let original_name = hdr.filename.clone();

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let temp_name = match &original_name {
        Some(name) => format!("{}_{}", uuid::Uuid::new_v4(), name),
        None => format!("dec_{}.bin", uuid::Uuid::new_v4()),
    };
    let temp_path = dir.join(&temp_name);

    let out_file = std::fs::File::create(&temp_path)
        .map_err(|e| format!("Failed to create temp file: {e}"))?;
    let mut out = BufWriter::new(out_file);

    let bytes_written = io::copy(&mut plaintext_reader, &mut out)
        .map_err(|e| {
            tracing::error!(error = %e, "File decryption failed");
            format!("Decryption failed: {e}")
        })? as usize;

    out.flush().map_err(|e| format!("flush: {e}"))?;
    drop(out);

    state.temp_files.lock().unwrap().push(temp_path.clone());

    // Detect file type from first bytes of the temp file
    let mut head_buf = vec![0u8; 8192.min(bytes_written)];
    if !head_buf.is_empty() {
        let mut f = std::fs::File::open(&temp_path)
            .map_err(|e| format!("reopen temp: {e}"))?;
        f.read_exact(&mut head_buf)
            .map_err(|e| format!("read head: {e}"))?;
    }

    let ft = file_type::detect_file_type(&head_buf);
    let (mime, extension, category) = match &ft {
        Some(f) => {
            let cat = file_type::classify_mime(&f.mime);
            (f.mime.clone(), f.extension.clone(), format!("{:?}", cat))
        }
        None => {
            if std::str::from_utf8(&head_buf).is_ok() {
                ("text/plain".into(), "txt".into(), "Text".into())
            } else {
                ("application/octet-stream".into(), "bin".into(), "Binary".into())
            }
        }
    };

    /// Size threshold for inline preview (10 MiB).
    const INLINE_PREVIEW_MAX: usize = 10 << 20;

    let (preview_base64, preview_data_url) = if bytes_written <= INLINE_PREVIEW_MAX {
        let data = std::fs::read(&temp_path).map_err(|e| format!("read temp: {e}"))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
        let data_url = format!("data:{};base64,{}", mime, b64);
        (Some(b64), Some(data_url))
    } else {
        (None, None)
    };

    tracing::info!(
        input_path = %input_path,
        plaintext_size = bytes_written,
        mime = %mime,
        "File decrypted"
    );

    Ok(DecryptFileResult {
        size: bytes_written,
        mime,
        extension,
        temp_path: temp_path.display().to_string(),
        category,
        preview_base64,
        preview_data_url,
        original_name,
    })
}

/// Decrypt a .himitsu file that contains a tar archive (folder).
#[tauri::command]
pub fn decrypt_to_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<DecryptFileResult, String> {
    let rk = {
        let db = state.db.lock().unwrap();
        super::keys::load_active_rk(&db)?
    };

    let file = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to open ciphertext file: {e}"))?;
    let reader = BufReader::new(file);

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let (hdr, mut plaintext_reader) =
        open_himitsu(bgw_sys, rk.bgw_index, &rk.usk_bytes, reader)?;

    let original_name = hdr.filename.clone();

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    // Stream directly into tar unpack — no intermediate buffer
    let mut archive = tar::Archive::new(&mut plaintext_reader);
    archive
        .unpack(&dir)
        .map_err(|e| format!("Failed to untar: {e}"))?;

    let top_dir = original_name
        .clone()
        .unwrap_or_else(|| format!("dir_{}", uuid::Uuid::new_v4()));
    let out_dir = dir.join(&top_dir);

    tracing::info!(
        input_path = %input_path,
        output_dir = %out_dir.display(),
        "Folder decrypted and extracted"
    );

    Ok(DecryptFileResult {
        size: 0,
        mime: "inode/directory".into(),
        extension: String::new(),
        temp_path: out_dir.display().to_string(),
        category: "Folder".into(),
        preview_base64: None,
        preview_data_url: None,
        original_name,
    })
}
