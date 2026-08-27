//! Bounded extraction and validation of image attachments embedded in Agent requests.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use serde_json::Value;

use crate::protocol::model::digest::sha256_bytes_hex;

/// Maximum number of images retained from one provider request.
pub const MAX_IMAGE_ATTACHMENTS_PER_EVENT: usize = 8;
/// Maximum aggregate decoded image bytes retained from one provider request.
pub const MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT: usize = 8 * 1024 * 1024;
const MAX_BASE64_IMAGE_CHARACTERS: usize = 11_184_812;

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

    fn matches_signature(self, bytes: &[u8]) -> bool {
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

/// Extracts images from OpenAI Responses and Chat Completions user content.
pub fn extract_openai_request_images(payload: &Value) -> Vec<ParsedImageAttachment> {
    let mut collector = ImageCollector::default();
    if let Some(input) = payload.get("input") {
        collector.collect_openai_input(input);
    }
    if let Some(messages) = payload.get("messages") {
        collector.collect_openai_input(messages);
    }
    collector.attachments
}

/// Extracts base64 images submitted by the latest Anthropic user message.
///
/// Anthropic requests replay the complete conversation on every provider call.
/// Restricting extraction to the latest user message prevents historical image
/// attachments from being uploaded again on each tool loop. Image blocks may
/// be direct user input or nested inside a Claude Code `tool_result`.
pub fn extract_anthropic_request_images(payload: &Value) -> Vec<ParsedImageAttachment> {
    let mut collector = ImageCollector::default();
    if let Some(messages) = payload.get("messages") {
        collector.collect_anthropic_messages(messages);
    }
    if let Some(input) = payload.get("input") {
        collector.collect_anthropic_messages(input);
    }
    collector.attachments
}

#[derive(Default)]
struct ImageCollector {
    attachments: Vec<ParsedImageAttachment>,
    decoded_bytes: usize,
}

impl ImageCollector {
    fn collect_openai_input(&mut self, value: &Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.collect_openai_input_item(item);
                    if self.is_full() {
                        break;
                    }
                }
            }
            Value::Object(_) => self.collect_openai_input_item(value),
            _ => {}
        }
    }

    fn collect_openai_input_item(&mut self, value: &Value) {
        let Some(object) = value.as_object() else {
            return;
        };
        let item_type = object.get("type").and_then(Value::as_str);
        if matches!(item_type, Some("input_image" | "image_url")) {
            let data_url = object.get("image_url").and_then(|value| {
                value
                    .as_str()
                    .or_else(|| value.get("url").and_then(Value::as_str))
            });
            if let Some(data_url) = data_url {
                self.push_data_url(data_url);
            }
            return;
        }

        let is_user_message = object.get("role").and_then(Value::as_str) == Some("user");
        if is_user_message && let Some(content) = object.get("content") {
            self.collect_openai_content(content);
        }
    }

    fn collect_openai_content(&mut self, value: &Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.collect_openai_input_item(item);
                    if self.is_full() {
                        break;
                    }
                }
            }
            Value::Object(_) => self.collect_openai_input_item(value),
            _ => {}
        }
    }

    fn collect_anthropic_messages(&mut self, value: &Value) {
        match value {
            Value::Array(items) => items
                .iter()
                .rev()
                .find(|item| item.get("role").and_then(Value::as_str) == Some("user"))
                .into_iter()
                .for_each(|item| self.collect_anthropic_message(item)),
            Value::Object(_) => self.collect_anthropic_message(value),
            _ => {}
        }
    }

    fn collect_anthropic_message(&mut self, value: &Value) {
        let Some(object) = value.as_object() else {
            return;
        };
        if object.get("role").and_then(Value::as_str) != Some("user") {
            return;
        }
        let Some(content) = object.get("content") else {
            return;
        };
        self.collect_anthropic_content(content);
    }

    fn collect_anthropic_content(&mut self, value: &Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.collect_anthropic_content(item);
                    if self.is_full() {
                        break;
                    }
                }
            }
            Value::Object(object) => match object.get("type").and_then(Value::as_str) {
                Some("image") => self.collect_anthropic_image(object),
                Some("tool_result") => {
                    if let Some(content) = object.get("content") {
                        self.collect_anthropic_content(content);
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn collect_anthropic_image(&mut self, image: &serde_json::Map<String, Value>) {
        let Some(source) = image.get("source").and_then(Value::as_object) else {
            return;
        };
        if source.get("type").and_then(Value::as_str) != Some("base64") {
            return;
        }
        let Some(media_type) = source.get("media_type").and_then(Value::as_str) else {
            return;
        };
        let Some(data) = source.get("data").and_then(Value::as_str) else {
            return;
        };
        self.push_base64(media_type, data);
    }

    fn push_data_url(&mut self, data_url: &str) {
        let Some(value) = data_url.strip_prefix("data:") else {
            return;
        };
        let Some((metadata, encoded)) = value.split_once(',') else {
            return;
        };
        let mut parts = metadata.split(';');
        let Some(media_type) = parts.next() else {
            return;
        };
        if !parts.any(|part| part.eq_ignore_ascii_case("base64")) {
            return;
        }
        self.push_base64(media_type, encoded);
    }

    fn push_base64(&mut self, media_type: &str, encoded: &str) {
        if self.is_full() {
            return;
        }
        let Some(media_type) = ImageMediaType::parse(media_type) else {
            return;
        };
        if encoded.len() > MAX_BASE64_IMAGE_CHARACTERS {
            return;
        }
        let remaining = MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT.saturating_sub(self.decoded_bytes);
        let Ok(bytes) = STANDARD.decode(encoded) else {
            return;
        };
        if bytes.is_empty() || bytes.len() > remaining || !media_type.matches_signature(&bytes) {
            return;
        }
        self.decoded_bytes = self.decoded_bytes.saturating_add(bytes.len());
        self.attachments.push(ParsedImageAttachment {
            media_type,
            sha256: sha256_bytes_hex(&bytes),
            bytes,
        });
    }

    const fn is_full(&self) -> bool {
        self.attachments.len() >= MAX_IMAGE_ATTACHMENTS_PER_EVENT
            || self.decoded_bytes >= MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;

    use super::{ImageMediaType, extract_anthropic_request_images, extract_openai_request_images};

    const PNG_BYTES: &[u8] = b"\x89PNG\r\n\x1a\nvalidated-image";
    const JPEG_BYTES: &[u8] = b"\xff\xd8\xffvalidated-image";
    const WEBP_BYTES: &[u8] = b"RIFF\x04\x00\x00\x00WEBPvalidated-image";
    const GIF_BYTES: &[u8] = b"GIF89avalidated-image";

    #[test]
    fn extracts_openai_input_image_from_user_content() {
        let data_url = format!("data:image/png;base64,{}", STANDARD.encode(PNG_BYTES));
        let payload = json!({
            "input": [{
                "type": "message",
                "role": "user",
                "content": [
                    {"type": "input_text", "text": "describe this"},
                    {"type": "input_image", "image_url": data_url}
                ]
            }]
        });

        let images = extract_openai_request_images(&payload);

        assert_eq!(images.len(), 1);
        assert_eq!(images[0].media_type, ImageMediaType::Png);
        assert_eq!(images[0].bytes, PNG_BYTES);
        assert_eq!(images[0].sha256.len(), 64);
    }

    #[test]
    fn extracts_anthropic_base64_image_from_user_content() {
        let payload = json!({
            "messages": [{
                "role": "user",
                "content": [{
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": "image/png",
                        "data": STANDARD.encode(PNG_BYTES)
                    }
                }]
            }]
        });

        let images = extract_anthropic_request_images(&payload);

        assert_eq!(images.len(), 1);
        assert_eq!(images[0].media_type, ImageMediaType::Png);
        assert_eq!(images[0].bytes, PNG_BYTES);
    }

    #[test]
    fn extracts_latest_anthropic_tool_result_image_without_replaying_history() {
        let payload = json!({
            "messages": [
                {
                    "role": "user",
                    "content": [{
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": STANDARD.encode(PNG_BYTES)
                        }
                    }]
                },
                {
                    "role": "assistant",
                    "content": [{"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {}}]
                },
                {
                    "role": "user",
                    "content": [{
                        "type": "tool_result",
                        "tool_use_id": "toolu_1",
                        "content": [{
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": "image/jpeg",
                                "data": STANDARD.encode(JPEG_BYTES)
                            }
                        }]
                    }]
                }
            ]
        });

        let images = extract_anthropic_request_images(&payload);

        assert_eq!(images.len(), 1);
        assert_eq!(images[0].media_type, ImageMediaType::Jpeg);
        assert_eq!(images[0].bytes, JPEG_BYTES);
    }

    #[test]
    fn does_not_reupload_historical_anthropic_image_on_later_text_turn() {
        let payload = json!({
            "messages": [
                {
                    "role": "user",
                    "content": [{
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": STANDARD.encode(PNG_BYTES)
                        }
                    }]
                },
                {"role": "assistant", "content": [{"type": "text", "text": "done"}]},
                {"role": "user", "content": "next question"}
            ]
        });

        assert!(extract_anthropic_request_images(&payload).is_empty());
    }

    #[test]
    fn extracts_every_supported_openai_image_media_type() {
        let fixtures = [
            ("image/png", PNG_BYTES, ImageMediaType::Png),
            ("image/jpeg", JPEG_BYTES, ImageMediaType::Jpeg),
            ("image/webp", WEBP_BYTES, ImageMediaType::Webp),
            ("image/gif", GIF_BYTES, ImageMediaType::Gif),
        ];
        let content = fixtures
            .iter()
            .map(|(media_type, bytes, _expected)| {
                json!({
                    "type": "input_image",
                    "image_url": format!(
                        "data:{media_type};base64,{}",
                        STANDARD.encode(bytes)
                    )
                })
            })
            .collect::<Vec<_>>();
        let payload = json!({
            "input": [{"type": "message", "role": "user", "content": content}]
        });

        let images = extract_openai_request_images(&payload);

        assert_eq!(images.len(), fixtures.len());
        for (image, (_media_type, bytes, expected)) in images.iter().zip(fixtures) {
            assert_eq!(image.media_type, expected);
            assert_eq!(image.bytes, bytes);
        }
    }

    #[test]
    fn rejects_remote_urls_active_media_and_mismatched_signatures() {
        let payload = json!({
            "input": [{
                "role": "user",
                "content": [
                    {"type": "input_image", "image_url": "https://example.invalid/image.png"},
                    {"type": "input_image", "image_url": "data:image/svg+xml;base64,PHN2Zz4="},
                    {"type": "input_image", "image_url": format!("data:image/jpeg;base64,{}", STANDARD.encode(PNG_BYTES))}
                ]
            }]
        });

        assert!(extract_openai_request_images(&payload).is_empty());
    }

    #[test]
    fn ignores_images_outside_user_message_content() {
        let data_url = format!("data:image/png;base64,{}", STANDARD.encode(PNG_BYTES));
        let payload = json!({
            "tools": [{"example": {"type": "input_image", "image_url": data_url}}],
            "input": [{
                "role": "developer",
                "content": [{"type": "input_image", "image_url": data_url}]
            }]
        });

        assert!(extract_openai_request_images(&payload).is_empty());
    }
}
