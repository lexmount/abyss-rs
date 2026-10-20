//! Chat Completions tool calls and results, independent of Harness identity.
//! Streamed inputs are assembled per tool index within one choice. Request
//! results preserve every tool message, including repeated history, in wire order.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::protocol::model::tool::ParsedToolEvent;

/// Tool calls belonging to one Chat Completions choice.
#[derive(Default)]
pub(super) struct ChatToolCalls {
    calls: BTreeMap<u64, ChatToolCall>,
}

impl ChatToolCalls {
    /// Accumulates input fragments, without decoding incomplete JSON arguments.
    pub fn apply_delta(&mut self, delta: &Value) {
        let Some(calls) = delta.get("tool_calls").and_then(Value::as_array) else {
            return;
        };
        for call in calls {
            if let Some(index) = call.get("index").and_then(Value::as_u64) {
                self.calls.entry(index).or_default().apply(call);
            }
        }
    }

    /// Replaces streamed calls with an authoritative non-streaming snapshot.
    pub fn reconcile(&mut self, message: &Value) {
        let Some(calls) = message.get("tool_calls").and_then(Value::as_array) else {
            return;
        };
        self.calls.clear();
        for (index, call) in calls.iter().enumerate() {
            let mut slot = ChatToolCall::default();
            slot.apply(call);
            self.calls
                .insert(u64::try_from(index).unwrap_or(u64::MAX), slot);
        }
    }

    pub fn events(&self) -> impl Iterator<Item = ParsedToolEvent> + '_ {
        self.calls.values().filter_map(ChatToolCall::event)
    }

    /// Observes every tool result the request carries without inferring freshness.
    pub fn request_results(payload: &Value) -> Vec<ParsedToolEvent> {
        let Some(messages) = payload.get("messages").and_then(Value::as_array) else {
            return Vec::new();
        };
        messages
            .iter()
            .filter(|message| message.get("role").and_then(Value::as_str) == Some("tool"))
            .filter_map(|message| {
                let call_id = message.get("tool_call_id")?.as_str()?;
                let content = message.get("content")?;
                let output = match content {
                    Value::String(text) => text.clone(),
                    Value::Array(parts) => parts
                        .iter()
                        .filter(|part| part.get("type").and_then(Value::as_str) == Some("text"))
                        .filter_map(|part| part.get("text").and_then(Value::as_str))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    _ => return None,
                };
                Some(ParsedToolEvent::ToolResult {
                    call_id: Some(call_id.to_owned()),
                    output,
                })
            })
            .collect()
    }
}

enum ChatToolKind {
    Function,
    Custom,
}

impl ChatToolKind {
    fn payload<'a>(&self, call: &'a Value) -> Option<(&'a Value, &'static str)> {
        match self {
            Self::Function => Some((call.get("function")?, "arguments")),
            Self::Custom => Some((call.get("custom")?, "input")),
        }
    }
}

#[derive(Default)]
struct ChatToolCall {
    id: Option<String>,
    name: Option<String>,
    kind: Option<ChatToolKind>,
    input: Option<String>,
}

impl ChatToolCall {
    fn apply(&mut self, call: &Value) {
        match call.get("type").and_then(Value::as_str) {
            Some("function") => self.kind = Some(ChatToolKind::Function),
            Some("custom") => self.kind = Some(ChatToolKind::Custom),
            Some(_) => return,
            None => {}
        }
        // Compatible streams may repeat empty metadata on argument-only chunks.
        if let Some(id) = call
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
        {
            self.id = Some(id.to_owned());
        }
        let Some((payload, input_key)) = self.kind.as_ref().and_then(|kind| kind.payload(call))
        else {
            return;
        };
        if let Some(name) = payload
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
        {
            self.name = Some(name.to_owned());
        }
        if let Some(fragment) = payload.get(input_key).and_then(Value::as_str) {
            self.input
                .get_or_insert_with(String::new)
                .push_str(fragment);
        }
    }

    fn event(&self) -> Option<ParsedToolEvent> {
        Some(ParsedToolEvent::ToolCall {
            item_id: None,
            call_id: self.id.clone(),
            name: self.name.clone(),
            input: self.input.clone()?,
        })
    }
}
