//! Indexed output text reconciliation, without protocol-specific tool state.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::MessageRole;
use serde_json::Value;

use super::content::{OpenAiContent, item_id, response_part_text, slot_index};
use crate::protocol::model::conversation::MessageDraft;

/// Text slots of one output item or chat choice, keyed by content index.
pub struct OutputText {
    /// Provider item identity.
    id: Option<String>,
    /// Role declared by the item or implied by the delta kind.
    role: MessageRole,
    /// Accumulated or reconciled text per content or summary index.
    pub parts: BTreeMap<u64, String>,
}

impl OutputText {
    pub const fn new(role: MessageRole) -> Self {
        Self {
            id: None,
            role,
            parts: BTreeMap::new(),
        }
    }

    /// Applies one authoritative snapshot to a part.
    ///
    /// A snapshot that extends the accumulated text only contributes the
    /// missing suffix, an equal one changes nothing, and a diverging one
    /// replaces it because the provider, not the accumulation, is authoritative.
    pub fn reconcile(&mut self, index: u64, authoritative: &str) {
        if authoritative.is_empty() {
            return;
        }
        let part = self.parts.entry(index).or_default();
        if let Some(suffix) = authoritative.strip_prefix(part.as_str()) {
            part.push_str(suffix);
        } else {
            authoritative.clone_into(part);
        }
    }

    /// Reconciles identity, role, and every text part of one item snapshot.
    pub fn reconcile_item(&mut self, item: &Value) {
        if let Some(id) = item_id(item) {
            self.id = Some(id);
        }
        self.role = OpenAiContent::item_role(item, MessageRole::Assistant);
        if self.role == MessageRole::Tool {
            return;
        }
        match item.get("content").or_else(|| item.get("summary")) {
            Some(Value::Array(parts)) => {
                for (index, part) in parts.iter().enumerate() {
                    if let Some(text) = response_part_text(part) {
                        self.reconcile(slot_index(index), text);
                    }
                }
            }
            Some(Value::String(text)) => self.reconcile(0, text),
            _ => {
                if let Some(text) = item.get("output_text").and_then(Value::as_str) {
                    self.reconcile(0, text);
                }
            }
        }
    }

    pub fn into_draft(self) -> MessageDraft {
        let mut draft = MessageDraft::new(self.role, self.id);
        if self.role != MessageRole::Tool {
            for part in self.parts.values() {
                draft.push_part(part);
            }
        }
        draft
    }
}
