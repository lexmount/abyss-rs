//! Chat Completions ordered `messages` history and `prompt`.
//!
//! Each message contributes, in order: its `reasoning_content` when the
//! assistant's thinking is preserved, one entry per content part, its
//! `refusal`, then one tool call per `tool_calls` element. A `tool` message is
//! the result of one call. Chat Completions entries carry no item identity.

use abyss_plugin_protocol::event::{
    ContentCompleteness, Conversation, ConversationEntry, EntryRole,
};
use serde_json::Value;

use super::tools::{message_call_entries, tool_message_entry};
use crate::protocol::{
    model::conversation::ConversationProjection, openai::shared::content::content_entries,
    shared::text::non_empty_trimmed,
};

/// Request-side entries.
pub struct ChatRequest {
    /// One entry per message part, call, or result, then the `prompt`.
    entries: Vec<ConversationEntry>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl ChatRequest {
    /// Projects one request body; `None` means it could not be decoded.
    #[must_use]
    pub fn parse(payload: Option<&Value>, truncated: bool) -> Self {
        let mut entries = Vec::new();
        for message in payload
            .and_then(|payload| payload.get("messages"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            message_entries(message, &mut entries);
        }
        if let Some(prompt) = payload
            .and_then(|payload| payload.get("prompt"))
            .and_then(Value::as_str)
            .filter(|prompt| non_empty_trimmed(prompt).is_some())
        {
            entries.push(ConversationProjection::text(EntryRole::User, prompt));
        }
        Self {
            entries,
            completeness: ConversationProjection::completeness(payload.is_some(), truncated),
        }
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_entries(self.entries.clone(), self.completeness)
    }
}

/// Appends the entries of one message.
fn message_entries(message: &Value, entries: &mut Vec<ConversationEntry>) {
    let role = message
        .get("role")
        .and_then(Value::as_str)
        .map_or(EntryRole::Unknown, ConversationProjection::role);
    if role == EntryRole::ToolResult {
        entries.push(tool_message_entry(message));
        return;
    }
    // Compatible APIs preserve the assistant's thinking alongside its content.
    if role == EntryRole::Assistant
        && let Some(reasoning) = message
            .get("reasoning_content")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    {
        entries.push(ConversationProjection::text(
            EntryRole::Reasoning,
            reasoning,
        ));
    }
    content_entries(message.get("content"), role, entries);
    if let Some(refusal) = message.get("refusal").and_then(Value::as_str) {
        entries.push(ConversationProjection::text(EntryRole::Assistant, refusal));
    }
    entries.extend(message_call_entries(message));
}
