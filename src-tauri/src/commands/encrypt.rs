//! File and folder encryption commands.

use tauri::State;

use crate::AppState;
use crate::crypto::bgw;
use crate::storage::models::EncryptFileResult;

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

    let db = state.db.lock().unwrap();
    let recipients = super::subscribers::get_active_recipient_indices(&db)?;
    drop(db);

    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let broadcast_ct = bgw::encrypt(bgw_sys, &recipients, &plaintext)
        .map_err(|e| e.to_string())?;

    let input_name = std::path::Path::new(&input_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "encrypted".into());

    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let output_path = dir.join(format!("{}.himitsu", input_name));

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
    use std::io::BufWriter;

    let src = std::path::Path::new(&input_path);
    if !src.is_dir() {
        return Err("Path is not a directory".into());
    }

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

    let db = state.db.lock().unwrap();
    let recipients = super::subscribers::get_active_recipient_indices(&db)?;
    drop(db);

    if recipients.is_empty() {
        return Err("No active subscribers to encrypt for".into());
    }

    let bgw_guard = state.bgw.lock().unwrap();
    let bgw_sys = bgw_guard.as_ref().ok_or("BGW system not initialized")?;

    let broadcast_ct = bgw::encrypt(bgw_sys, &recipients, &tar_buf)
        .map_err(|e| e.to_string())?;

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
        input_size, output_size,
        "Folder encrypted"
    );

    Ok(EncryptFileResult {
        input_size,
        output_size,
        output_path: output_path.display().to_string(),
    })
}
