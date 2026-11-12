//! Anthropic request image field traversal; decoding limits are shared.

use serde_json::Value;

use crate::protocol::{model::image::ParsedImageAttachment, shared::image::ImageCollector};

/// Extracts base64 images from every Anthropic user message, including those
/// nested inside a `tool_result`.
pub fn extract_anthropic_request_images(payload: &Value) -> Vec<ParsedImageAttachment> {
    let mut collector = RequestImages::default();
    if let Some(messages) = payload.get("messages") {
        collector.collect_anthropic_messages(messages);
    }
    if let Some(input) = payload.get("input") {
        collector.collect_anthropic_messages(input);
    }
    collector.collector.attachments
}

#[derive(Default)]
struct RequestImages {
    collector: ImageCollector,
}

impl RequestImages {
    fn collect_anthropic_messages(&mut self, value: &Value) {
        match value {
            Value::Array(items) => items
                .iter()
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
                    if self.collector.is_full() {
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
        self.collector.push_base64(media_type, data);
    }
}
