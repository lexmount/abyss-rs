//! Chat Completions messages and choices.
//!
//! Requests carry `messages`; responses carry `choices`, either whole or as
//! streamed deltas. A `tool` message is the result of one call, and an
//! assistant message carries its calls in `tool_calls` and a refusal in
//! `refusal`. Chat Completions entries carry no item identity.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use super::{
    CallSlot, OpenAiContent, OpenAiRequest, OpenAiResponse, OutputSlot, Projection, SlotBody,
    output_text, slot_index,
};

/// Appends the entries of `messages`.
pub(super) fn push_request(request: &mut OpenAiRequest, payload: &Value) {
    for message in payload
        .get("messages")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        request.carries_messages = true;
        OpenAiContent::item_entries(message, EntryRole::Unknown, &mut request.entries);
    }
}

/// The entry of a `tool` message: the result of one call.
pub(super) fn tool_message_entry(message: &Value) -> ConversationEntry {
    Projection::tool_result(
        Projection::field(message, "tool_call_id"),
        message.get("content").map(output_text).unwrap_or_default(),
    )
}

/// Appends a message's `refusal` and its `tool_calls`, after its content.
pub(super) fn message_extra_entries(message: &Value, entries: &mut Vec<ConversationEntry>) {
    if let Some(refusal) = message.get("refusal").and_then(Value::as_str) {
        entries.push(Projection::text(EntryRole::Assistant, refusal));
    }
    for call in message
        .get("tool_calls")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        entries.push(Projection::tool_call(
            Projection::field(call, "id"),
            call.pointer("/function/name")
                .and_then(Value::as_str)
                .map(str::to_owned),
            call.pointer("/function/arguments")
                .map(Projection::verbatim)
                .unwrap_or_default(),
        ));
    }
}

/// Applies the `choices` of one whole or streamed document.
pub(super) fn apply_choices(slots: &mut BTreeMap<u64, OutputSlot>, choices: &[Value]) {
    for choice in choices {
        let index = choice["index"].as_u64().unwrap_or(0);
        if let Some(message) = choice.get("message") {
            OpenAiResponse::reconcile_item(slots, index, message);
        }
        let slot = slots
            .entry(index)
            .or_insert_with(|| OutputSlot::new(SlotBody::message()));
        let fragment = choice
            .pointer("/delta/content")
            .or_else(|| choice.get("text"))
            .and_then(Value::as_str);
        if let Some(fragment) = fragment
            && let Some(part) = slot.text_part(0)
        {
            part.push_str(fragment);
        }
        if let SlotBody::Message { calls, .. } = &mut slot.body {
            for call in choice
                .pointer("/delta/tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                push_call_delta(calls, call);
            }
        }
    }
}

/// Replaces streamed chat tool calls with a final message's calls.
pub(super) fn reconcile_calls(calls: &mut BTreeMap<u64, CallSlot>, message: &Value) {
    let Some(message_calls) = message.get("tool_calls").and_then(Value::as_array) else {
        return;
    };
    for (position, call) in message_calls.iter().enumerate() {
        let index = call["index"]
            .as_u64()
            .unwrap_or_else(|| slot_index(position));
        let slot = calls.entry(index).or_default();
        slot.call_id = Projection::field(call, "id").or_else(|| slot.call_id.take());
        slot.name = call
            .pointer("/function/name")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| slot.name.take());
        if let Some(arguments) = call.pointer("/function/arguments") {
            slot.input = Projection::verbatim(arguments);
        }
    }
}

/// Accumulates one streamed chat `delta.tool_calls` fragment.
fn push_call_delta(calls: &mut BTreeMap<u64, CallSlot>, call: &Value) {
    let slot = calls
        .entry(call["index"].as_u64().unwrap_or(0))
        .or_default();
    if let Some(id) = Projection::field(call, "id") {
        slot.call_id = Some(id);
    }
    if let Some(name) = call.pointer("/function/name").and_then(Value::as_str) {
        slot.name = Some(name.to_owned());
    }
    if let Some(arguments) = call.pointer("/function/arguments").and_then(Value::as_str) {
        slot.streamed.push_str(arguments);
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::tests::summary;
    use super::*;

    #[test]
    fn chat_choices_are_independent_and_carry_their_tool_calls() {
        let values = vec![
            json!({"choices":[{"index":0_i32,"delta":{"content":"hel"}},{"index":1_i32,"delta":{"content":"other"}}]}),
            json!({"choices":[{"index":0_i32,"delta":{"content":"lo"}}]}),
            json!({"choices":[{"index":1_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"call_9","function":{"name":"lookup","arguments":"{\"q\":"}}]}}]}),
            json!({"choices":[{"index":1_i32,"delta":{"tool_calls":[{"index":0_i32,"function":{"arguments":"1}"}}]}}]}),
            json!({"id":"chatcmpl-1","choices":[{"index":0_i32,"message":{"role":"assistant","content":"corrected"}}]}),
        ];
        let conversation = OpenAiResponse::assemble(&values, false).conversation();
        assert!(
            conversation
                .entries
                .iter()
                .all(|entry| entry.item_id.is_none())
        );

        assert_eq!(
            summary(&conversation),
            [
                (EntryRole::Assistant, "corrected", None, None),
                (EntryRole::Assistant, "other", None, None),
                (
                    EntryRole::ToolCall,
                    "{\"q\":1}",
                    Some("call_9"),
                    Some("lookup")
                ),
            ]
        );
    }

    #[test]
    fn chat_request_maps_tool_calls_and_tool_messages() {
        let request = OpenAiRequest::parse(
            Some(&json!({"messages":[
                {"role":"system","content":"rules"},
                {"role":"user","content":[{"type":"text","text":"hi"}]},
                {"role":"assistant","content":null,"tool_calls":[
                    {"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"q\":1}"}}
                ]},
                {"role":"tool","tool_call_id":"call_1","content":"found"}
            ]})),
            false,
        );
        assert!(
            request
                .conversation()
                .entries
                .iter()
                .all(|entry| entry.item_id.is_none())
        );

        assert_eq!(
            summary(&request.conversation()),
            [
                (EntryRole::System, "rules", None, None),
                (EntryRole::User, "hi", None, None),
                (
                    EntryRole::ToolCall,
                    "{\"q\":1}",
                    Some("call_1"),
                    Some("lookup")
                ),
                (EntryRole::ToolResult, "found", Some("call_1"), None),
            ]
        );
    }
}
