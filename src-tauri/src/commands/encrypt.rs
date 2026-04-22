//! File, folder, and in-memory content encryption commands.

use std::io::{BufReader, BufWriter};

use tauri::State;

use crate::AppState;
use crate::crypto::bgw;
use crate::storage::models::EncryptFileResult;

/// Shared helper: encrypt from a reader into a temp HMT2 file.
///
/// Returns `(output_path, output_size)`.
fn encrypt_to_temp<R: std::io::Read>(
    input: &mut R,
    state: &State<'_, AppState>,
    recipients: &[u32],
    filename: Option<String>,
    is_folder: bool,
) -> std::result::Result<(std::path::PathBuf, u64), String> {
    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", uuid::Uuid::new_v4()));

    let file = std::fs::File::create(&output_path)
        .map_err(|e| format!("Failed to create output file: {e}"))?;
    let mut writer = BufWriter::new(file);

    bgw::encrypt(bgw_sys, recipients, input, &mut writer, filename, is_folder)
        .map_err(|e| e.to_string())?;

    drop(writer);

    let output_size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    state.temp_files.lock().unwrap().push(output_path.clone());

    Ok((output_path, output_size))
}

/// Encrypt a file on disk using BGW broadcast encryption.
///
/// Encrypts for all non-revoked users.
#[tauri::command]
pub fn encrypt_file(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    let file = std::fs::File::open(&input_path)
        .map_err(|e| format!("Failed to read input file: {e}"))?;
    let input_size = file.metadata()
        .map(|m| m.len())
        .map_err(|e| format!("Failed to get file size: {e}"))?;
    let mut reader = BufReader::new(file);

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

    let (output_path, output_size) = encrypt_to_temp(
        &mut reader, &state, &recipients, Some(input_name.clone()), false,
    )?;

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

/// Encrypt a folder: tar -> encrypt -> single .himitsu temp file.
#[tauri::command]
pub fn encrypt_folder(
    input_path: String,
    state: State<'_, AppState>,
) -> std::result::Result<EncryptFileResult, String> {
    let src = std::path::Path::new(&input_path);
    if !src.is_dir() {
        return Err("Path is not a directory".into());
    }

    // Tar the directory into memory, then stream into zstd via encrypt.
    let mut tar_buf = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_buf);
        let dir_name = src.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "folder".into());
        builder.append_dir_all(&dir_name, src)
            .map_err(|e| format!("Failed to tar directory: {e}"))?;
        builder.finish()
            .map_err(|e| format!("Failed to finalize tar: {e}"))?;
    }
    let input_size = tar_buf.len() as u64;

    let recipients = {
        let db = state.db.lock().unwrap();
        super::subscribers::get_active_recipient_indices(&db)?
    };

    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let folder_name = src.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "folder".into());

    let mut cursor = std::io::Cursor::new(&tar_buf);
    let (output_path, output_size) = encrypt_to_temp(
        &mut cursor, &state, &recipients, Some(folder_name.clone()), true,
    )?;

    tracing::info!(
        input_path = %input_path,
        output_path = %output_path.display(),
        input_size, output_size,
        "Folder encrypted"
    );

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}

/// Encrypt in-memory content (e.g. browser-dragged images).
///
/// Accepts base64-encoded plaintext + original filename, encrypts for all
/// non-revoked users, writes the ciphertext to a temp file.
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

    let mut cursor = std::io::Cursor::new(&plaintext);
    let (output_path, output_size) = encrypt_to_temp(
        &mut cursor, &state, &recipients, Some(filename.clone()), false,
    )?;

    tracing::info!(filename = %filename, input_size, output_size, "Content encrypted");

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}
