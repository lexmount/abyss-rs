//! Streamed output under assembly, reconciled with provider snapshots, without
//! protocol-specific item state.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use super::content::{response_part_text, slot_index};
use crate::protocol::model::conversation::ConversationProjection;

/// Applies one authoritative snapshot to accumulated text.
///
/// A snapshot that extends the accumulated text only contributes the missing
/// suffix, an equal one changes nothing, and a diverging one replaces it
/// because the provider, not the accumulation, is authoritative.
pub fn reconcile(text: &mut String, authoritative: &str) {
    if authoritative.is_empty() {
        return;
    }
    if let Some(suffix) = authoritative.strip_prefix(text.as_str()) {
        text.push_str(suffix);
    } else {
        authoritative.clone_into(text);
    }
}

/// One content part of an output message.
enum Part {
    /// Text in the message's role.
    Text(String),
    /// A refusal, always the assistant's.
    Refusal(String),
}

/// The content parts of one output message, by content index.
#[derive(Default)]
pub struct MessageParts {
    parts: BTreeMap<u64, Part>,
}

impl MessageParts {
    /// The text of a part, created empty when absent; none for a refusal.
    pub fn text_part(&mut self, index: u64) -> Option<&mut String> {
        match self
            .parts
            .entry(index)
            .or_insert_with(|| Part::Text(String::new()))
        {
            Part::Text(text) => Some(text),
            Part::Refusal(_) => None,
        }
    }

    /// Reconciles one text part with an authoritative snapshot.
    pub fn reconcile(&mut self, index: u64, authoritative: &str) {
        if !authoritative.is_empty()
            && let Some(text) = self.text_part(index)
        {
            reconcile(text, authoritative);
        }
    }

    /// Reconciles the text and refusal parts of a message snapshot: its
    /// `content` array or string, or else its `output_text`.
    pub fn reconcile_content(&mut self, message: &Value) {
        match message.get("content") {
            Some(Value::Array(parts)) => {
                for (index, part) in parts.iter().enumerate() {
                    let index = slot_index(index);
                    if let Some(text) = response_part_text(part) {
                        self.reconcile(index, text);
                    } else if part.get("type").and_then(Value::as_str) == Some("refusal")
                        && let Some(refusal) = part.get("refusal").and_then(Value::as_str)
                    {
                        self.parts.insert(index, Part::Refusal(refusal.to_owned()));
                    }
                }
            }
            Some(Value::String(text)) => self.reconcile(0, text),
            _ => {
                if let Some(text) = message.get("output_text").and_then(Value::as_str) {
                    self.reconcile(0, text);
                }
            }
        }
    }

    /// One entry per part: text in `role`, a refusal as the assistant's.
    pub fn entries(&self, role: EntryRole) -> impl Iterator<Item = ConversationEntry> + '_ {
        self.parts.values().map(move |part| match part {
            Part::Text(text) => ConversationProjection::text(role, text),
            Part::Refusal(text) => ConversationProjection::text(EntryRole::Assistant, text),
        })
    }
}

/// A tool call under assembly.
#[derive(Default)]
pub struct CallSlot {
    pub call_id: Option<String>,
    pub name: Option<String>,
    /// Arguments or input from the latest snapshot that carried them.
    pub input: String,
    /// Arguments or input accumulated from streamed deltas.
    pub streamed: String,
}

impl CallSlot {
    /// The call's entry: the snapshot input when one arrived, otherwise the
    /// streamed input.
    pub fn entry(&self) -> ConversationEntry {
        ConversationProjection::tool_call(
            self.call_id.clone(),
            self.name.clone(),
            if self.input.is_empty() {
                self.streamed.clone()
            } else {
                self.input.clone()
            },
        )
    }
}
