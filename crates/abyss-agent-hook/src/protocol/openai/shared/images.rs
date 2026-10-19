//! Openai request image field traversal; decoding limits are shared.

use serde_json::Value;

use crate::protocol::{model::image::ParsedImageAttachment, shared::image::ImageCollector};

/// Extracts images from OpenAI Responses and Chat Completions user content.
pub fn extract_openai_request_images(payload: &Value) -> Vec<ParsedImageAttachment> {
    let mut collector = RequestImages::default();
    if let Some(input) = payload.get("input") {
        collector.collect_openai_input(input);
    }
    if let Some(messages) = payload.get("messages") {
        collector.collect_openai_input(messages);
    }
    collector.collector.attachments
}

#[derive(Default)]
struct RequestImages {
    collector: ImageCollector,
}

impl RequestImages {
    fn collect_openai_input(&mut self, value: &Value) {
        match value {
            Value::Array(items) => {
                for item in items {
                    self.collect_openai_input_item(item);
                    if self.collector.is_full() {
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
                self.collector.push_data_url(data_url);
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
                    if self.collector.is_full() {
                        break;
                    }
                }
            }
            Value::Object(_) => self.collect_openai_input_item(value),
            _ => {}
        }
    }
}
