//! OpenAI-family content parts and item projection; protocol state lives in each dialect.

use abyss_plugin_protocol::event::MessageRole;
use serde_json::Value;

use crate::protocol::{
    model::conversation::{ConversationProjection, MessageDraft},
    shared::text::{MAX_PARSE_DEPTH, visible_text},
};

/// OpenAI-specific text, tool-item, and message-item rules.
pub struct OpenAiContent;

impl OpenAiContent {
    /// Returns the visible text of a content value, skipping tool items.
    #[must_use]
    pub fn text(value: &Value, depth: usize) -> Option<String> {
        visible_text(value, depth, Self::is_tool_item)
    }

    /// Whether an item or part type carries tool calls or tool results.
    #[must_use]
    pub fn is_tool_item(item_type: &str) -> bool {
        matches!(item_type, "tool_call" | "tool_result" | "tool_use")
            || item_type.ends_with("_call")
            || item_type.ends_with("_call_output")
    }

    /// Role of one request or response item.
    pub fn item_role(item: &Value, default_role: MessageRole) -> MessageRole {
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => MessageRole::Reasoning,
            Some(kind) if Self::is_tool_item(kind) => MessageRole::Tool,
            _ => item
                .get("role")
                .and_then(Value::as_str)
                .map_or(default_role, ConversationProjection::role),
        }
    }

    /// Projects one request item; content parts stay separate fragments.
    pub fn request_item(item: &Value, default_role: MessageRole) -> MessageDraft {
        let role = Self::item_role(item, default_role);
        let mut draft = MessageDraft::new(role, item_id(item));
        let content = if role == MessageRole::Reasoning {
            item.get("summary")
        } else {
            item.get("content")
        };
        match (role, content) {
            (MessageRole::Tool, _) => {}
            (_, Some(Value::Array(parts))) => {
                for part in parts {
                    draft.push_part(
                        &Self::text(part, MAX_PARSE_DEPTH.saturating_sub(1)).unwrap_or_default(),
                    );
                }
            }
            (MessageRole::Reasoning, _) => {}
            _ => draft.push_part(&Self::text(item, MAX_PARSE_DEPTH).unwrap_or_default()),
        }
        draft
    }
}

/// Returns the text of one response part, excluding refusals and tools.
pub fn response_part_text(part: &Value) -> Option<&str> {
    match part {
        Value::String(text) => Some(text),
        Value::Object(object) => {
            let text_part = object
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| {
                    matches!(kind, "output_text" | "text" | "summary_text" | "input_text")
                });
            text_part
                .then(|| object.get("text").and_then(Value::as_str))
                .flatten()
        }
        _ => None,
    }
}

pub fn item_id(item: &Value) -> Option<String> {
    item.get("id").and_then(Value::as_str).map(str::to_owned)
}

pub fn slot_index(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}
