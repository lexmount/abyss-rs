//! Responses output items and streaming deltas, reconciled by output/content index.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::MessageRole;
use serde_json::Value;

use super::tools::tool_call;
use crate::protocol::{
    model::{conversation::ConversationProjection, tool::ParsedToolEvent},
    openai::shared::{
        content::{response_part_text, slot_index},
        output::OutputText,
        response::OpenAiResponse,
    },
};

struct ResponsesSlot {
    text: OutputText,
    tool_call: Option<ParsedToolEvent>,
}

impl ResponsesSlot {
    const fn new(role: MessageRole) -> Self {
        Self {
            text: OutputText::new(role),
            tool_call: None,
        }
    }
    fn reconcile_item(&mut self, item: &Value) {
        self.text.reconcile_item(item);
        if let Some(call) = tool_call(item) {
            self.tool_call = Some(call);
        }
    }
}

pub struct ResponsesResponse;
impl ResponsesResponse {
    pub fn assemble(values: &[Value], incomplete: bool) -> OpenAiResponse {
        let mut slots = BTreeMap::new();
        for value in values {
            Self::apply(&mut slots, value);
        }
        let tool_calls = slots
            .values()
            .filter_map(|slot| slot.tool_call.clone())
            .collect();
        OpenAiResponse {
            messages: slots
                .into_values()
                .map(|slot| slot.text.into_draft())
                .collect(),
            tool_calls,
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }
    fn apply(slots: &mut BTreeMap<u64, ResponsesSlot>, value: &Value) {
        let output_index = value["output_index"].as_u64().unwrap_or(0);
        let part_index = value
            .get("content_index")
            .or_else(|| value.get("summary_index"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let reasoning_role = |kind: &str| {
            if kind.starts_with("response.reasoning") {
                MessageRole::Reasoning
            } else {
                MessageRole::Assistant
            }
        };
        match value["type"].as_str().unwrap_or_default() {
            kind @ ("response.output_text.delta" | "response.reasoning_summary_text.delta") => {
                if let Some(delta) = value["delta"].as_str() {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| ResponsesSlot::new(reasoning_role(kind)))
                        .text
                        .parts
                        .entry(part_index)
                        .or_default()
                        .push_str(delta);
                }
            }
            kind @ ("response.output_text.done" | "response.reasoning_summary_text.done") => {
                if let Some(text) = value["text"].as_str() {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| ResponsesSlot::new(reasoning_role(kind)))
                        .text
                        .reconcile(part_index, text);
                }
            }
            kind @ ("response.content_part.done" | "response.reasoning_summary_part.done") => {
                if let Some(text) = value.get("part").and_then(response_part_text) {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| ResponsesSlot::new(reasoning_role(kind)))
                        .text
                        .reconcile(part_index, text);
                }
            }
            "response.output_item.added" | "response.output_item.done" => {
                if let Some(item) = value.get("item") {
                    Self::reconcile_item(slots, output_index, item);
                }
            }
            "response.completed" | "response.done" => {
                if let Some(output) = value.pointer("/response/output").and_then(Value::as_array) {
                    for (index, item) in output.iter().enumerate() {
                        Self::reconcile_item(slots, slot_index(index), item);
                    }
                }
            }
            _ => Self::apply_document(slots, value),
        }
    }

    /// Applies a non-streaming Responses object.
    fn apply_document(slots: &mut BTreeMap<u64, ResponsesSlot>, value: &Value) {
        if let Some(output) = value.get("output").and_then(Value::as_array) {
            for (index, item) in output.iter().enumerate() {
                Self::reconcile_item(slots, slot_index(index), item);
            }
        } else if value.get("output_text").is_some() || value.get("content").is_some() {
            Self::reconcile_item(slots, 0, value);
        }
    }

    fn reconcile_item(slots: &mut BTreeMap<u64, ResponsesSlot>, index: u64, item: &Value) {
        slots
            .entry(index)
            .or_insert_with(|| ResponsesSlot::new(MessageRole::Assistant))
            .reconcile_item(item);
    }
}
