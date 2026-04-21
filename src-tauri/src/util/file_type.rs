//! File type detection and classification utilities.
//!
//! Provides MIME detection via magic bytes, inline-rendering classification
//! for the WebView frontend, and temporary file management.

use crate::error::Result;
use crate::storage::models::{InlineCategory, RenderAction};
use std::path::PathBuf;

/// Detected file type info from magic bytes.
pub struct FileTypeInfo {
    pub mime: String,
    pub extension: String,
}

/// MIME types that WebView / Chromium can render natively.
const INLINE_IMAGE: &[&str] = &[
    "image/png", "image/jpeg", "image/gif", "image/webp",
    "image/svg+xml", "image/bmp", "image/x-icon",
];
const INLINE_VIDEO: &[&str] = &[
    "video/mp4", "video/webm", "video/ogg",
];
const INLINE_AUDIO: &[&str] = &[
    "audio/mpeg", "audio/ogg", "audio/wav", "audio/webm",
    "audio/aac", "audio/flac",
];
const INLINE_TEXT: &[&str] = &[
    "text/plain", "text/html", "text/css", "text/csv",
    "text/xml", "text/javascript", "application/json",
    "application/xml",
];

/// Detect the file type of binary content using magic bytes.
pub fn detect_file_type(data: &[u8]) -> Option<FileTypeInfo> {
    infer::get(data).map(|t| FileTypeInfo {
        mime: t.mime_type().to_string(),
        extension: t.extension().to_string(),
    })
}

/// Decide how to present decrypted content to the user.
pub fn decide_render_action(data: &[u8], file_type: Option<&FileTypeInfo>) -> RenderAction {
    let Some(ft) = file_type else {
        if std::str::from_utf8(data).is_ok() {
            let b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                data,
            );
            return RenderAction::Inline {
                mime: "text/plain".into(),
                extension: "txt".into(),
                data_base64: b64.clone(),
                data_url: format!("data:text/plain;base64,{}", b64),
                category: InlineCategory::Text,
            };
        }
        let preview_len = data.len().min(256);
        return RenderAction::Unknown {
            size_bytes: data.len(),
            hex_preview: hex::encode(&data[..preview_len]),
        };
    };

    let mime = ft.mime.as_str();
    let cat = classify_mime(mime);
    if !matches!(cat, InlineCategory::Binary) {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        );
        return RenderAction::Inline {
            mime: ft.mime.clone(),
            extension: ft.extension.clone(),
            data_base64: b64.clone(),
            data_url: format!("data:{};base64,{}", ft.mime, b64),
            category: cat,
        };
    }

    RenderAction::External {
        mime: ft.mime.clone(),
        extension: ft.extension.clone(),
        temp_path: String::new(),
    }
}

/// Write decrypted bytes to a temporary file and open with system default app.
///
/// Returns the path to the temp file (caller must register for cleanup).
pub fn write_temp_and_open(data: &[u8], extension: &str) -> Result<PathBuf> {
    let dir = std::env::temp_dir().join("himitsu");
    std::fs::create_dir_all(&dir)?;

    let filename = format!("dec_{}.{}", uuid::Uuid::new_v4(), extension);
    let path = dir.join(filename);
    std::fs::write(&path, data)?;

    open::that(&path)
        .map_err(crate::error::HimitsuError::Io)?;

    Ok(path)
}

/// Classify a MIME type into a rendering category for the frontend.
pub fn classify_mime(mime: &str) -> InlineCategory {
    if INLINE_IMAGE.contains(&mime) {
        InlineCategory::Image
    } else if INLINE_VIDEO.contains(&mime) {
        InlineCategory::Video
    } else if INLINE_AUDIO.contains(&mime) {
        InlineCategory::Audio
    } else if INLINE_TEXT.contains(&mime) {
        InlineCategory::Text
    } else if mime == "application/pdf" {
        InlineCategory::Pdf
    } else {
        InlineCategory::Binary
    }
}
