//! OpenAI-family content parts, shared by both dialects; items, messages, and
//! tool calls belong to each dialect.

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use crate::protocol::{
    model::conversation::ConversationProjection,
    shared::text::{self, MAX_PARSE_DEPTH, json_to_text},
};

/// The entry of one message content part, by the part-to-role table: text
/// parts take the message's role, a refusal is the assistant's, a tool part
/// yields none, and any other part keeps its visible text in the message's
/// role.
pub fn part_entry(part: &Value, role: EntryRole) -> Option<ConversationEntry> {
    if let Value::String(text) = part {
        return Some(ConversationProjection::text(role, text));
    }
    match part.get("type").and_then(Value::as_str) {
        Some("input_text" | "output_text" | "text" | "summary_text" | "reasoning_text") => {
            Some(ConversationProjection::text(
                role,
                &ConversationProjection::field(part, "text").unwrap_or_default(),
            ))
        }
        Some("refusal") => Some(ConversationProjection::text(
            EntryRole::Assistant,
            &ConversationProjection::field(part, "refusal").unwrap_or_default(),
        )),
        _ => visible_text(part).map(|text| ConversationProjection::text(role, &text)),
    }
}

/// Whether a part or item type carries a tool call or result.
pub fn is_tool_type(kind: &str) -> bool {
    matches!(kind, "tool_call" | "tool_result" | "tool_use")
        || kind.ends_with("_call")
        || kind.ends_with("_call_output")
}

/// The visible text of a value, skipping tool parts and items.
pub fn visible_text(value: &Value) -> Option<String> {
    text::visible_text(value, MAX_PARSE_DEPTH, is_tool_type)
}

/// Appends the entries of a message's `content`: one entry for a string, one
/// per part for an array.
pub fn content_entries(
    content: Option<&Value>,
    role: EntryRole,
    entries: &mut Vec<ConversationEntry>,
) {
    match content {
        Some(Value::String(text)) => entries.push(ConversationProjection::text(role, text)),
        Some(Value::Array(parts)) => {
            entries.extend(parts.iter().filter_map(|part| part_entry(part, role)));
        }
        _ => {}
    }
}

/// A tool output: a string as sent, otherwise its text parts or its JSON.
pub fn output_text(output: &Value) -> String {
    match output {
        Value::String(text) => text.clone(),
        value => json_to_text(value, MAX_PARSE_DEPTH)
            .unwrap_or_else(|| ConversationProjection::verbatim(value)),
    }
}

/// The text of one response part, excluding refusals and tools.
pub fn response_part_text(part: &Value) -> Option<&str> {
    match part {
        Value::String(text) => Some(text),
        Value::Object(object) => {
            let text_part = object
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| {
                    matches!(
                        kind,
                        "output_text" | "text" | "summary_text" | "reasoning_text" | "input_text"
                    )
                });
            text_part
                .then(|| object.get("text").and_then(Value::as_str))
                .flatten()
        }
        _ => None,
    }
}

pub fn slot_index(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}
