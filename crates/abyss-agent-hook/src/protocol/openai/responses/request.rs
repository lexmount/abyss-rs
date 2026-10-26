//! Responses request `instructions`, `input` items, and `prompt`.
//!
//! Every input item is classified once by the item-to-role table in
//! [`item_entries`]: `reasoning` contributes one entry, every `*_call` a tool
//! call, every `*_output` a tool result, and a message or any other item one
//! entry per content part, or its visible text, in the item's role.
//! `instructions` take the developer role. Every entry of an item carries the
//! item's `id` verbatim.

use abyss_plugin_protocol::event::{
    ContentCompleteness, Conversation, ConversationEntry, EntryRole,
};
use serde_json::Value;

use super::{
    response::reasoning_text,
    tools::{call_entry, output_entry},
};
use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::content::{content_entries, visible_text},
    shared::text::non_empty_trimmed,
};

/// Request-side entries.
pub struct ResponsesRequest {
    /// Whether the request carried a message-bearing field: `instructions`, a
    /// non-empty `input`, or a non-blank `prompt`.
    carries_messages: bool,
    /// One entry per item or part: `instructions`, `input`, then `prompt`.
    entries: Vec<ConversationEntry>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl ResponsesRequest {
    /// Projects one request body; `None` means it could not be decoded.
    #[must_use]
    pub fn parse(payload: Option<&Value>, truncated: bool) -> Self {
        let mut request = Self {
            carries_messages: false,
            entries: Vec::new(),
            completeness: ConversationProjection::completeness(payload.is_some(), truncated),
        };
        let Some(payload) = payload else {
            return request;
        };
        request.push_instructions(payload.get("instructions"));
        request.push_input(payload.get("input"));
        if let Some(prompt) = payload
            .get("prompt")
            .and_then(Value::as_str)
            .filter(|prompt| non_empty_trimmed(prompt).is_some())
        {
            request.carries_messages = true;
            request
                .entries
                .push(ConversationProjection::text(EntryRole::User, prompt));
        }
        request
    }

    fn push_instructions(&mut self, instructions: Option<&Value>) {
        match instructions {
            Some(Value::String(text)) => {
                self.carries_messages = true;
                self.entries
                    .push(ConversationProjection::text(EntryRole::Developer, text));
            }
            Some(Value::Array(items)) => {
                self.carries_messages = true;
                for item in items {
                    item_entries(item, EntryRole::Developer, &mut self.entries);
                }
            }
            Some(Value::Null) | None => {}
            Some(other) => {
                self.carries_messages = true;
                self.entries.extend(
                    visible_text(other)
                        .map(|text| ConversationProjection::text(EntryRole::Developer, &text)),
                );
            }
        }
    }

    fn push_input(&mut self, input: Option<&Value>) {
        match input {
            Some(Value::Array(items)) => {
                self.carries_messages |= !items.is_empty();
                for item in items {
                    let role = if item.is_string() {
                        EntryRole::User
                    } else {
                        EntryRole::Unknown
                    };
                    item_entries(item, role, &mut self.entries);
                }
            }
            Some(Value::String(text)) => {
                self.carries_messages = true;
                self.entries
                    .push(ConversationProjection::text(EntryRole::User, text));
            }
            Some(item @ Value::Object(_)) => {
                self.carries_messages = true;
                item_entries(item, EntryRole::Unknown, &mut self.entries);
            }
            _ => {}
        }
    }

    /// Whether the request carried no message-bearing field.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.carries_messages
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_entries(self.entries.clone(), self.completeness)
    }
}

/// Appends the entries of one item by the item-to-role table, each carrying
/// the item's `id`.
fn item_entries(item: &Value, default_role: EntryRole, entries: &mut Vec<ConversationEntry>) {
    let start = entries.len();
    if let Value::String(text) = item {
        entries.push(ConversationProjection::text(default_role, text));
        return;
    }
    match item.get("type").and_then(Value::as_str) {
        Some("reasoning") => entries.push(ConversationProjection::text(
            EntryRole::Reasoning,
            &reasoning_text(item).unwrap_or_default(),
        )),
        Some(kind) if kind.ends_with("_call") => entries.push(call_entry(item)),
        Some(kind) if kind.ends_with("_output") => entries.push(output_entry(item)),
        _ => message_entries(item, default_role, entries),
    }
    ConversationProjection::identify(
        &mut entries[start..],
        item.get("id").and_then(Value::as_str),
    );
}

/// The entries of a message or any other item, in the item's role: one per
/// content part, or else its visible text.
fn message_entries(item: &Value, default_role: EntryRole, entries: &mut Vec<ConversationEntry>) {
    let role = item
        .get("role")
        .and_then(Value::as_str)
        .map_or(default_role, ConversationProjection::role);
    match item.get("content") {
        Some(content @ (Value::String(_) | Value::Array(_))) => {
            content_entries(Some(content), role, entries);
        }
        _ => {
            if let Some(text) = visible_text(item) {
                entries.push(ConversationProjection::text(role, &text));
            }
        }
    }
}
