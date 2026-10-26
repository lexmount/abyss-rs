//! Responses `output` items and `response.*` stream events, reconciled by
//! output and content index.
//!
//! Streamed deltas replay onto one slot per output item, and provider
//! snapshots reconcile them, so an answer republished by several terminal
//! events is reported once. Every item is classified by the item-to-role
//! table in [`SlotBody`], and every entry of an item carries its `id`.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use super::tools::{output_entry, reconcile_call};
use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{
        content::{response_part_text, slot_index},
        output::{CallSlot, MessageParts, reconcile},
        response::OpenAiResponse,
    },
};

/// What one output item holds, by the item-to-role table.
enum SlotBody {
    /// A message or any other item: its parts by content index.
    Message(MessageParts),
    /// A `reasoning` item: its content, or else summary, parts by index.
    Reasoning(BTreeMap<u64, String>),
    /// A `*_call` item.
    ToolCall(CallSlot),
    /// A `*_output` item.
    ToolResult(ConversationEntry),
}

impl SlotBody {
    /// The empty body of an item of `item_type`.
    fn for_item(item_type: Option<&str>) -> Self {
        match item_type {
            Some("reasoning") => Self::Reasoning(BTreeMap::new()),
            Some(kind) if kind.ends_with("_call") => Self::ToolCall(CallSlot::default()),
            Some(kind) if kind.ends_with("_output") => {
                Self::ToolResult(ConversationProjection::tool_result(None, String::new()))
            }
            _ => Self::Message(MessageParts::default()),
        }
    }
}

/// One output item under assembly.
struct ResponsesSlot {
    /// The output item's `id`.
    item_id: Option<String>,
    /// Role declared by the item, or assistant.
    role: EntryRole,
    /// What the item holds.
    body: SlotBody,
}

impl ResponsesSlot {
    const fn new(body: SlotBody) -> Self {
        Self {
            item_id: None,
            role: EntryRole::Assistant,
            body,
        }
    }

    /// The slot a text event of `kind` starts: reasoning or a message.
    fn for_text_event(kind: &str) -> Self {
        Self::new(if kind.starts_with("response.reasoning") {
            SlotBody::Reasoning(BTreeMap::new())
        } else {
            SlotBody::Message(MessageParts::default())
        })
    }

    /// The text of a message or reasoning part, created empty when absent;
    /// none for other items and for a refusal part.
    fn text_part(&mut self, index: u64) -> Option<&mut String> {
        match &mut self.body {
            SlotBody::Message(parts) => parts.text_part(index),
            SlotBody::Reasoning(parts) => Some(parts.entry(index).or_default()),
            _ => None,
        }
    }

    fn reconcile(&mut self, index: u64, authoritative: &str) {
        if !authoritative.is_empty()
            && let Some(text) = self.text_part(index)
        {
            reconcile(text, authoritative);
        }
    }

    /// Reconciles the body and role with one item snapshot. A snapshot of
    /// another kind than the body was started as replaces it.
    fn reconcile_item(&mut self, item: &Value) {
        let body = SlotBody::for_item(item.get("type").and_then(Value::as_str));
        if std::mem::discriminant(&body) != std::mem::discriminant(&self.body) {
            self.body = body;
        }
        self.role = item
            .get("role")
            .and_then(Value::as_str)
            .map_or(EntryRole::Assistant, ConversationProjection::role);
        match &mut self.body {
            SlotBody::Message(parts) => parts.reconcile_content(item),
            SlotBody::Reasoning(_) => {
                for (index, text) in reasoning_parts(item).unwrap_or_default() {
                    self.reconcile(index, text);
                }
            }
            SlotBody::ToolCall(call) => reconcile_call(call, item),
            SlotBody::ToolResult(entry) => *entry = output_entry(item),
        }
    }

    /// The item's entries, each carrying the item's identity.
    fn entries(&self) -> Vec<ConversationEntry> {
        let mut entries = match &self.body {
            SlotBody::Message(parts) => parts.entries(self.role).collect(),
            SlotBody::Reasoning(parts) => vec![ConversationProjection::text(
                EntryRole::Reasoning,
                &parts.values().cloned().collect::<Vec<_>>().join("\n"),
            )],
            SlotBody::ToolCall(call) => vec![call.entry()],
            SlotBody::ToolResult(entry) => vec![entry.clone()],
        };
        ConversationProjection::identify(&mut entries, self.item_id.as_deref());
        entries
    }
}

/// Responses output assembly.
pub struct ResponsesResponse;

impl ResponsesResponse {
    /// Assembles one response from its decoded documents in arrival order.
    #[must_use]
    pub fn assemble(values: &[Value], incomplete: bool) -> OpenAiResponse {
        let mut slots = BTreeMap::new();
        for value in values {
            if !Self::apply_event(&mut slots, value) {
                Self::apply_document(&mut slots, value);
            }
        }
        OpenAiResponse {
            empty: slots.is_empty(),
            entries: slots.values().flat_map(ResponsesSlot::entries).collect(),
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }

    /// Applies one `response.*` stream event; returns whether `value` was one.
    fn apply_event(slots: &mut BTreeMap<u64, ResponsesSlot>, value: &Value) -> bool {
        let output_index = value["output_index"].as_u64().unwrap_or(0);
        let part_index = value
            .get("content_index")
            .or_else(|| value.get("summary_index"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        match value["type"].as_str().unwrap_or_default() {
            kind @ ("response.output_text.delta"
            | "response.reasoning_summary_text.delta"
            | "response.reasoning_text.delta") => {
                if let Some(delta) = value["delta"].as_str()
                    && let Some(part) = slots
                        .entry(output_index)
                        .or_insert_with(|| ResponsesSlot::for_text_event(kind))
                        .text_part(part_index)
                {
                    part.push_str(delta);
                }
            }
            kind @ ("response.output_text.done"
            | "response.reasoning_summary_text.done"
            | "response.reasoning_text.done") => {
                if let Some(text) = value["text"].as_str() {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| ResponsesSlot::for_text_event(kind))
                        .reconcile(part_index, text);
                }
            }
            kind @ ("response.content_part.done" | "response.reasoning_summary_part.done") => {
                if let Some(text) = value.get("part").and_then(response_part_text) {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| ResponsesSlot::for_text_event(kind))
                        .reconcile(part_index, text);
                }
            }
            "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta" => {
                if let Some(delta) = value["delta"].as_str()
                    && let SlotBody::ToolCall(call) = &mut slots
                        .entry(output_index)
                        .or_insert_with(|| {
                            ResponsesSlot::new(SlotBody::ToolCall(CallSlot::default()))
                        })
                        .body
                {
                    call.streamed.push_str(delta);
                }
            }
            "response.output_item.added" | "response.output_item.done" => {
                if let Some(item) = value.get("item") {
                    Self::reconcile_output_item(slots, output_index, item);
                }
            }
            "response.completed" | "response.done" => {
                if let Some(output) = value.pointer("/response/output").and_then(Value::as_array) {
                    Self::apply_output(slots, output);
                }
            }
            _ => return false,
        }
        true
    }

    /// Applies a non-streaming Responses object.
    fn apply_document(slots: &mut BTreeMap<u64, ResponsesSlot>, value: &Value) {
        if let Some(output) = value.get("output").and_then(Value::as_array) {
            Self::apply_output(slots, output);
        } else if value.get("output_text").is_some() || value.get("content").is_some() {
            Self::slot(slots, 0).reconcile_item(value);
        }
    }

    fn apply_output(slots: &mut BTreeMap<u64, ResponsesSlot>, output: &[Value]) {
        for (index, item) in output.iter().enumerate() {
            Self::reconcile_output_item(slots, slot_index(index), item);
        }
    }

    /// Reconciles one output item, which carries its `id`.
    fn reconcile_output_item(slots: &mut BTreeMap<u64, ResponsesSlot>, index: u64, item: &Value) {
        let slot = Self::slot(slots, index);
        slot.reconcile_item(item);
        slot.item_id = ConversationProjection::field(item, "id").or_else(|| slot.item_id.take());
    }

    fn slot(slots: &mut BTreeMap<u64, ResponsesSlot>, index: u64) -> &mut ResponsesSlot {
        slots
            .entry(index)
            .or_insert_with(|| ResponsesSlot::new(SlotBody::Message(MessageParts::default())))
    }
}

/// The text of one `reasoning` item: its content, or else its summary.
pub fn reasoning_text(item: &Value) -> Option<String> {
    reasoning_parts(item).map(|parts| {
        parts
            .into_iter()
            .map(|(_, text)| text)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// The non-empty text parts of a `reasoning` item's content, or else of its
/// summary, by their index.
fn reasoning_parts(item: &Value) -> Option<Vec<(u64, &str)>> {
    ["content", "summary"].iter().find_map(|key| {
        let parts = item
            .get(*key)
            .and_then(Value::as_array)?
            .iter()
            .enumerate()
            .filter_map(|(index, part)| {
                let text = part.get("text").and_then(Value::as_str)?;
                (!text.is_empty()).then(|| (slot_index(index), text))
            })
            .collect::<Vec<_>>();
        (!parts.is_empty()).then_some(parts)
    })
}
