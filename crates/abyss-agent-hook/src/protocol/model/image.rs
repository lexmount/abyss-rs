//! Validated provider-neutral image types and capture limits.

use std::fmt;

use serde::Serialize;

use crate::protocol::shared::digest::sha256_bytes_hex;

/// Maximum number of images retained from one provider request.
pub const MAX_IMAGE_ATTACHMENTS_PER_EVENT: usize = 8;
/// Maximum aggregate decoded image bytes retained from one provider request.
pub const MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT: usize = 8 * 1024 * 1024;

/// Browser-safe raster media types accepted by the audit pipeline.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ImageMediaType {
    #[serde(rename = "image/png")]
    Png,
    #[serde(rename = "image/jpeg")]
    Jpeg,
    #[serde(rename = "image/webp")]
    Webp,
    #[serde(rename = "image/gif")]
    Gif,
}

impl ImageMediaType {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "image/png" => Some(Self::Png),
            "image/jpeg" | "image/jpg" => Some(Self::Jpeg),
            "image/webp" => Some(Self::Webp),
            "image/gif" => Some(Self::Gif),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
            Self::Gif => "image/gif",
        }
    }

    pub fn matches_signature(self, bytes: &[u8]) -> bool {
        match self {
            Self::Png => bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
            Self::Jpeg => bytes.starts_with(b"\xff\xd8\xff"),
            Self::Webp => {
                bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP"
            }
            Self::Gif => bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a"),
        }
    }
}

impl fmt::Display for ImageMediaType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One validated image carried in a provider request.
#[derive(Clone, Debug)]
pub struct ParsedImageAttachment {
    pub media_type: ImageMediaType,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl ParsedImageAttachment {
    /// Validates one decoded provider image against the shared audit limits.
    pub fn from_bytes(media_type: &str, bytes: &[u8]) -> Option<Self> {
        let media_type = ImageMediaType::parse(media_type)?;
        if bytes.is_empty()
            || bytes.len() > MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT
            || !media_type.matches_signature(bytes)
        {
            return None;
        }
        Some(Self {
            media_type,
            bytes: bytes.to_vec(),
            sha256: sha256_bytes_hex(bytes),
        })
    }

    pub const fn byte_size(&self) -> usize {
        self.bytes.len()
    }
}
