//! File info and temp file management commands.

use crate::storage::models::FileInfo;
use crate::util::file_type;

/// Size threshold for inline preview (10 MiB).
const INLINE_PREVIEW_MAX: usize = 10 << 20;

/// Return file/directory info for a given path.
///
/// For small renderable files (< 10 MiB), also returns preview data.
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

    if size <= INLINE_PREVIEW_MAX as u64 {
        if let Ok(data) = std::fs::read(p) {
            let ft = file_type::detect_file_type(&data);
            let (mime, category) = match &ft {
                Some(f) => {
                    let cat = file_type::classify_mime(&f.mime);
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

/// Copy a temp file to a user-chosen destination.
#[tauri::command]
pub fn save_temp_file(
    temp_path: String,
    dest_path: String,
) -> std::result::Result<(), String> {
    let src = std::path::Path::new(&temp_path);
    let dst = std::path::Path::new(&dest_path);
    if src.is_dir() {
        copy_dir_recursive(src, dst).map_err(|e| format!("Failed to save folder: {e}"))?;
    } else {
        std::fs::copy(src, dst)
            .map_err(|e| format!("Failed to save file: {e}"))?;
    }
    tracing::info!(src = %temp_path, dest = %dest_path, "Temp file saved");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
