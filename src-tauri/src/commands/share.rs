//! Share commands for Android: share files out to other apps.

use serde::Serialize;

/// Result returned after sharing a file.
#[derive(Debug, Clone, Serialize)]
pub struct ShareResult {
    pub success: bool,
    pub message: String,
}

/// Share a file to other apps via the system share sheet.
///
/// On Android, this creates a content:// URI via FileProvider and launches
/// an ACTION_SEND intent. On desktop, this is a no-op (drag-out is used instead).
#[tauri::command]
pub fn share_file(
    file_path: String,
    mime_type: Option<String>,
) -> std::result::Result<ShareResult, String> {
    #[cfg(target_os = "android")]
    {
        share_file_android(&file_path, mime_type.as_deref())
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = (&file_path, &mime_type);
        Ok(ShareResult {
            success: false,
            message: "Share not supported on desktop (use drag-out instead)".into(),
        })
    }
}

/// Detect whether a file is a Himitsu ciphertext (HMT2 magic bytes).
#[tauri::command]
pub fn is_himitsu_file(file_path: String) -> std::result::Result<bool, String> {
    let path = std::path::Path::new(&file_path);
    if !path.exists() {
        return Err("File not found".into());
    }
    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;
    let mut magic = [0u8; 4];
    use std::io::Read;
    match file.read_exact(&mut magic) {
        Ok(_) => Ok(&magic == crate::crypto::bgw::MAGIC),
        Err(_) => Ok(false), // file too small
    }
}

/// Detect whether base64-encoded data is a Himitsu ciphertext (HMT2 magic bytes).
#[tauri::command]
pub fn is_himitsu_data(data_base64: String) -> std::result::Result<bool, String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&data_base64)
        .map_err(|e| format!("Invalid base64: {e}"))?;
    Ok(bytes.len() >= 4 && &bytes[0..4] == crate::crypto::bgw::MAGIC)
}

#[cfg(target_os = "android")]
fn share_file_android(
    file_path: &str,
    mime_type: Option<&str>,
) -> std::result::Result<ShareResult, String> {
    use std::path::Path;

    let path = Path::new(file_path);
    if !path.exists() {
        return Err(format!("File not found: {file_path}"));
    }

    // Copy the file to the app's cache directory so FileProvider can access it
    let cache_dir = std::env::temp_dir().join("himitsu_share");
    std::fs::create_dir_all(&cache_dir).map_err(|e| e.to_string())?;

    let filename = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "shared_file".into());
    let share_path = cache_dir.join(&filename);
    std::fs::copy(path, &share_path)
        .map_err(|e| format!("Failed to copy file for sharing: {e}"))?;

    let mime = mime_type
        .map(String::from)
        .unwrap_or_else(|| "application/octet-stream".into());

    tracing::info!(
        path = %share_path.display(),
        mime = %mime,
        "File prepared for sharing"
    );

    // The actual Android Intent launch happens from the frontend via
    // the Kotlin side. We return the prepared file path.
    Ok(ShareResult {
        success: true,
        message: share_path.display().to_string(),
    })
}
