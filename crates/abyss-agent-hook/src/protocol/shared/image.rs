//! Bounded base64 and data-URL image decoding, independent of request schemas.

use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::protocol::{
    model::image::{
        ImageMediaType, MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT, MAX_IMAGE_ATTACHMENTS_PER_EVENT,
        ParsedImageAttachment,
    },
    shared::digest::sha256_bytes_hex,
};

const MAX_BASE64_IMAGE_CHARACTERS: usize = 11_184_812;

#[derive(Default)]
pub struct ImageCollector {
    pub attachments: Vec<ParsedImageAttachment>,
    decoded_bytes: usize,
}

impl ImageCollector {
    pub fn push_data_url(&mut self, data_url: &str) {
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

    pub fn push_base64(&mut self, media_type: &str, encoded: &str) {
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

    pub const fn is_full(&self) -> bool {
        self.attachments.len() >= MAX_IMAGE_ATTACHMENTS_PER_EVENT
            || self.decoded_bytes >= MAX_IMAGE_ATTACHMENT_BYTES_PER_EVENT
    }
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use serde_json::json;

    use crate::protocol::{
        anthropic::shared::images::extract_anthropic_request_images, model::image::ImageMediaType,
        openai::shared::images::extract_openai_request_images,
    };

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
