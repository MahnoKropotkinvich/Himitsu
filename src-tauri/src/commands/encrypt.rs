//! File, folder, and in-memory content encryption commands.
//!
//! Streaming pipeline: input → zstd::Encoder(mt) → ChunkEncryptor → File
//! Memory usage: O(chunk_size) regardless of input size.

use std::io::{self, BufReader, BufWriter};
use tauri::State;

use crate::AppState;
use crate::crypto::bgw::{self, BroadcastHeader, ChunkEncryptor, CHUNK_SIZE};
use crate::storage::models::EncryptFileResult;

/// Build the streaming encrypt pipeline and return the output file size.
///
/// 1. BGW encapsulate → (bgw_header, aes_key)
/// 2. Write magic + BroadcastHeader
/// 3. zstd::Encoder(ChunkEncryptor(File)) — compressed chunks written on the fly
fn streaming_encrypt<R: io::Read>(
    bgw_sys: &bgw::BgwSystem,
    recipients: &[u32],
    mut input: R,
    output_path: &std::path::Path,
    filename: Option<String>,
    is_folder: bool,
) -> std::result::Result<u64, String> {
    let (bgw_header, aes_key) = bgw_sys
        .encapsulate(recipients)
        .map_err(|e| e.to_string())?;

    let base_nonce: [u8; 8] = rand::random();

    let hdr = BroadcastHeader {
        header: bgw_header,
        recipients: recipients.to_vec(),
        nonce: base_nonce.to_vec(),
        chunk_size: CHUNK_SIZE,
        is_folder,
        filename,
    };

    let file = std::fs::File::create(output_path)
        .map_err(|e| format!("Failed to create output file: {e}"))?;
    let mut out = BufWriter::new(file);

    bgw::write_file_header(&mut out, &hdr).map_err(|e| e.to_string())?;

    let chunk_enc = ChunkEncryptor::new(out, aes_key, base_nonce, CHUNK_SIZE);
    let mut zstd_enc = zstd::Encoder::new(chunk_enc, 3)
        .map_err(|e| format!("zstd init: {e}"))?;
    let _ = zstd_enc.set_parameter(
        zstd::zstd_safe::CParameter::NbWorkers(num_cpus::get() as u32),
    );

    io::copy(&mut input, &mut zstd_enc)
        .map_err(|e| format!("streaming encrypt: {e}"))?;

    let chunk_enc = zstd_enc.finish().map_err(|e| format!("zstd finish: {e}"))?;
    chunk_enc.finish().map_err(|e| format!("chunk flush: {e}"))?;

    let output_size = std::fs::metadata(output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    Ok(output_size)
}

/// Encrypt a file on disk using BGW broadcast encryption.
#[tauri::command]
pub fn encrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    let input_size = std::fs::metadata(&input_path)
        .map_err(|e| format!("Failed to stat input file: {e}"))?
        .len();

    let recipients = {
        let db = state.db.lock().unwrap();
        super::subscribers::get_active_recipient_indices(&db)?
    };
    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let input_name = std::path::Path::new(&input_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "encrypted".into());

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", uuid::Uuid::new_v4()));

    let input = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to open input file: {e}"))?;
    let reader = BufReader::new(input);

    let output_size = streaming_encrypt(
        bgw_sys,
        &recipients,
        reader,
        &output_path,
        Some(input_name.clone()),
        false,
    )?;

    state.temp_files.lock().unwrap().push(output_path.clone());

    tracing::info!(
        input_path = %input_path,
        output_path = %output_path.display(),
        input_size, output_size,
        "File encrypted"
    );

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}

/// Encrypt a folder: tar → zstd → AES-GCM chunks → .himitsu temp file.
///
/// tar::Builder writes directly into the zstd encoder, which feeds
/// ChunkEncryptor. No intermediate tar buffer in memory.
#[tauri::command]
pub fn encrypt_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    let src = std::path::Path::new(&input_path);
    if !src.is_dir() {
        return Err("Path is not a directory".into());
    }

    let recipients = {
        let db = state.db.lock().unwrap();
        super::subscribers::get_active_recipient_indices(&db)?
    };
    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let folder_name = src
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "folder".into());

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    // BGW encapsulate
    let (bgw_header, aes_key) = bgw_sys
        .encapsulate(&recipients)
        .map_err(|e| e.to_string())?;
    let base_nonce: [u8; 8] = rand::random();

    let hdr = BroadcastHeader {
        header: bgw_header,
        recipients: recipients.to_vec(),
        nonce: base_nonce.to_vec(),
        chunk_size: CHUNK_SIZE,
        is_folder: true,
        filename: Some(folder_name.clone()),
    };

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", uuid::Uuid::new_v4()));

    let file = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {e}"))?;
    let mut out = BufWriter::new(file);

    bgw::write_file_header(&mut out, &hdr).map_err(|e| e.to_string())?;

    // Pipeline: tar::Builder → zstd::Encoder → ChunkEncryptor → File
    let chunk_enc = ChunkEncryptor::new(out, aes_key, base_nonce, CHUNK_SIZE);
    let mut zstd_enc = zstd::Encoder::new(chunk_enc, 3)
        .map_err(|e| format!("zstd init: {e}"))?;
    let _ = zstd_enc.set_parameter(
        zstd::zstd_safe::CParameter::NbWorkers(num_cpus::get() as u32),
    );

    {
        let mut tar_builder = tar::Builder::new(&mut zstd_enc);
        tar_builder
            .append_dir_all(&folder_name, src)
            .map_err(|e| format!("Failed to tar directory: {e}"))?;
        tar_builder
            .finish()
            .map_err(|e| format!("Failed to finalize tar: {e}"))?;
    }

    let chunk_enc = zstd_enc.finish().map_err(|e| format!("zstd finish: {e}"))?;
    chunk_enc.finish().map_err(|e| format!("chunk flush: {e}"))?;

    let output_size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    state.temp_files.lock().unwrap().push(output_path.clone());

    tracing::info!(
        input_path = %input_path,
        output_path = %output_path.display(),
        output_size,
        "Folder encrypted"
    );

    Ok(EncryptFileResult {
        input_size: 0, // tar size unknown in streaming mode
        output_size,
        output_path: output_path.display().to_string(),
    })
}

/// Encrypt in-memory content (e.g. browser-dragged images).
///
/// Accepts base64-encoded plaintext + original filename.
#[tauri::command]
pub fn encrypt_content(
    data_base64: String,
    filename: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    use base64::Engine;

    let plaintext = base64::engine::general_purpose::STANDARD
        .decode(&data_base64)
        .map_err(|e| format!("Invalid base64: {e}"))?;
    let input_size = plaintext.len() as u64;

    let recipients = {
        let db = state.db.lock().unwrap();
        super::subscribers::get_active_recipient_indices(&db)?
    };
    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", uuid::Uuid::new_v4()));

    let cursor = std::io::Cursor::new(plaintext);
    let output_size = streaming_encrypt(
        bgw_sys,
        &recipients,
        cursor,
        &output_path,
        Some(filename.clone()),
        false,
    )?;

    state.temp_files.lock().unwrap().push(output_path.clone());

    tracing::info!(filename = %filename, input_size, output_size, "Content encrypted");

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}
