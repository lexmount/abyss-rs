//! Chat Completions tool calls and results. A call is a `function` call with
//! `arguments` or a `custom` call with `input`; streamed inputs are assembled
//! per tool index within one choice.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::ConversationEntry;
use serde_json::Value;

use crate::protocol::{
    model::conversation::ConversationProjection,
    openai::shared::{
        content::{output_text, slot_index},
        output::CallSlot,
    },
};

/// The entry of a `tool` message: the result of one call.
pub fn tool_message_entry(message: &Value) -> ConversationEntry {
    ConversationProjection::tool_result(
        ConversationProjection::field(message, "tool_call_id"),
        message.get("content").map(output_text).unwrap_or_default(),
    )
}

/// One tool-call entry per element of a message's `tool_calls`, as sent.
pub fn message_call_entries(message: &Value) -> impl Iterator<Item = ConversationEntry> + '_ {
    message
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|call| {
            ConversationProjection::tool_call(
                ConversationProjection::field(call, "id"),
                call_name(call).map(str::to_owned),
                call_input(call)
                    .map(ConversationProjection::verbatim)
                    .unwrap_or_default(),
            )
        })
}

/// Tool calls belonging to one choice, by tool index.
#[derive(Default)]
pub struct ChatToolCalls {
    calls: BTreeMap<u64, CallSlot>,
}

impl ChatToolCalls {
    /// Accumulates one streamed `delta.tool_calls` array. Compatible streams
    /// repeat an empty `id` and `name` on argument-only fragments.
    pub fn apply_delta(&mut self, delta: &Value) {
        for call in delta
            .get("tool_calls")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let slot = self
                .calls
                .entry(call["index"].as_u64().unwrap_or(0))
                .or_default();
            if let Some(id) = ConversationProjection::field(call, "id").filter(|id| !id.is_empty())
            {
                slot.call_id = Some(id);
            }
            if let Some(name) = call_name(call).filter(|name| !name.is_empty()) {
                slot.name = Some(name.to_owned());
            }
            if let Some(input) = call_input(call).and_then(Value::as_str) {
                slot.streamed.push_str(input);
            }
        }
    }

    /// Replaces streamed calls with an authoritative message snapshot.
    pub fn reconcile(&mut self, message: &Value) {
        let Some(calls) = message.get("tool_calls").and_then(Value::as_array) else {
            return;
        };
        self.calls = calls
            .iter()
            .enumerate()
            .map(|(position, call)| {
                let slot = CallSlot {
                    call_id: ConversationProjection::field(call, "id"),
                    name: call_name(call).map(str::to_owned),
                    input: call_input(call)
                        .map(ConversationProjection::verbatim)
                        .unwrap_or_default(),
                    streamed: String::new(),
                };
                (slot_index(position), slot)
            })
            .collect();
    }

    pub fn entries(&self) -> impl Iterator<Item = ConversationEntry> + '_ {
        self.calls.values().map(CallSlot::entry)
    }
}

/// The `function` or `custom` payload of one call, with its input key.
fn call_payload(call: &Value) -> Option<(&Value, &'static str)> {
    call.get("function")
        .map(|function| (function, "arguments"))
        .or_else(|| call.get("custom").map(|custom| (custom, "input")))
}

fn call_name(call: &Value) -> Option<&str> {
    let (payload, _) = call_payload(call)?;
    payload.get("name").and_then(Value::as_str)
}

/// The `arguments` of a function call or the `input` of a custom call.
fn call_input(call: &Value) -> Option<&Value> {
    let (payload, key) = call_payload(call)?;
    payload.get(key)
}
