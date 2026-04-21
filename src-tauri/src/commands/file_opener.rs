use crate::error::Result;
use std::path::PathBuf;

/// Detected file type info.
pub struct FileTypeInfo {
    pub mime: String,
    pub extension: String,
}

/// How the frontend should handle the decrypted content.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "kind")]
pub enum RenderAction {
    /// Content can be rendered inline by the WebView.
    /// `data_url` is a complete `data:` URI ready for src= attributes
    /// or direct display.
    Inline {
        mime: String,
        extension: String,
        /// base64-encoded data for embedding
        data_base64: String,
        /// Pre-built data URI: `data:<mime>;base64,<data>`
        data_url: String,
        category: InlineCategory,
    },
    /// Content must be opened with an external system application.
    External {
        mime: String,
        extension: String,
        /// Path to the temp file written to disk.
        temp_path: String,
    },
    /// File type unknown; provide raw hex preview + option to save.
    Unknown {
        size_bytes: usize,
        hex_preview: String,
    },
}

/// What kind of inline rendering the frontend should use.
#[derive(Debug, Clone, serde::Serialize)]
pub enum InlineCategory {
    Image,
    Video,
    Audio,
    Text,
    Pdf,
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

/// Detect the file type of decrypted content using magic bytes.
pub fn detect_file_type(data: &[u8]) -> Option<FileTypeInfo> {
    infer::get(data).map(|t| FileTypeInfo {
        mime: t.mime_type().to_string(),
        extension: t.extension().to_string(),
    })
}

/// Decide how to present the decrypted content to the user.
pub fn decide_render_action(data: &[u8], file_type: Option<&FileTypeInfo>) -> RenderAction {
    let Some(ft) = file_type else {
        // Try to detect if it's valid UTF-8 text
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
        // Truly unknown binary
        let preview_len = data.len().min(256);
        return RenderAction::Unknown {
            size_bytes: data.len(),
            hex_preview: hex::encode(&data[..preview_len]),
        };
    };

    let mime = ft.mime.as_str();

    // Check if WebView can render it inline
    if let Some(cat) = classify_inline(mime) {
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

    // PDF: WebView can render via <embed> or <iframe>
    if mime == "application/pdf" {
        let b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            data,
        );
        return RenderAction::Inline {
            mime: ft.mime.clone(),
            extension: ft.extension.clone(),
            data_base64: b64.clone(),
            data_url: format!("data:application/pdf;base64,{}", b64),
            category: InlineCategory::Pdf,
        };
    }

    // Fall back to external application
    RenderAction::External {
        mime: ft.mime.clone(),
        extension: ft.extension.clone(),
        temp_path: String::new(), // filled by caller after writing temp file
    }
}

/// Write decrypted bytes to a temporary file with the correct extension
/// and open it using the system's default application.
///
/// Returns the path to the temp file (caller must register it for
/// cleanup when the application exits).
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

fn classify_inline(mime: &str) -> Option<InlineCategory> {
    if INLINE_IMAGE.contains(&mime) {
        Some(InlineCategory::Image)
    } else if INLINE_VIDEO.contains(&mime) {
        Some(InlineCategory::Video)
    } else if INLINE_AUDIO.contains(&mime) {
        Some(InlineCategory::Audio)
    } else if INLINE_TEXT.contains(&mime) {
        Some(InlineCategory::Text)
    } else {
        None
    }
}
