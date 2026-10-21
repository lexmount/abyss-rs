//! Responses API items and stream events.
//!
//! Requests carry `instructions` and `input` items; responses carry `output`
//! items, either whole or as `response.*` stream events. The non-message
//! items are `reasoning`, every `*_call`, and every `*_output`, and every
//! entry of an item carries the item's `id` verbatim.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use super::{
    CallSlot, OpenAiContent, OpenAiRequest, OpenAiResponse, OutputSlot, Projection, SlotBody,
    output_text, response_part_text, slot_index,
};

/// Appends the entries of `instructions` and `input`.
pub(super) fn push_request(request: &mut OpenAiRequest, payload: &Value) {
    let entries = &mut request.entries;
    match payload.get("instructions") {
        Some(Value::String(text)) => {
            request.carries_messages = true;
            entries.push(Projection::text(EntryRole::System, text));
        }
        Some(Value::Array(items)) => {
            request.carries_messages = true;
            for item in items {
                item_entries(item, EntryRole::System, entries);
            }
        }
        Some(Value::Null) | None => {}
        Some(other) => {
            request.carries_messages = true;
            entries.extend(Projection::unknown(other));
        }
    }
    match payload.get("input") {
        Some(Value::Array(items)) => {
            request.carries_messages |= !items.is_empty();
            for item in items {
                let role = if item.is_string() {
                    EntryRole::User
                } else {
                    EntryRole::Unknown
                };
                item_entries(item, role, entries);
            }
        }
        Some(Value::String(text)) => {
            request.carries_messages = true;
            entries.push(Projection::text(EntryRole::User, text));
        }
        Some(item @ Value::Object(_)) => {
            request.carries_messages = true;
            item_entries(item, EntryRole::Unknown, entries);
        }
        _ => {}
    }
}

/// Appends the entries of one Responses item, each carrying the item's `id`
/// verbatim.
fn item_entries(item: &Value, default_role: EntryRole, entries: &mut Vec<ConversationEntry>) {
    let start = entries.len();
    OpenAiContent::item_entries(item, default_role, entries);
    Projection::identify(
        &mut entries[start..],
        item.get("id").and_then(Value::as_str),
    );
}

/// The tool-call entry of one `*_call` item.
pub(super) fn call_entry(item: &Value) -> ConversationEntry {
    Projection::tool_call(
        Projection::field(item, "call_id"),
        Projection::field(item, "name"),
        call_input(item),
    )
}

/// The arguments or input of one `*_call` item, as sent.
fn call_input(item: &Value) -> String {
    [
        "arguments",
        "input",
        "action",
        "code",
        "queries",
        "operation",
    ]
    .iter()
    .find_map(|key| item.get(*key))
    .map(Projection::verbatim)
    .unwrap_or_default()
}

/// The tool-result entry of one `*_output` item.
pub(super) fn output_entry(item: &Value) -> ConversationEntry {
    Projection::tool_result(
        Projection::field(item, "call_id"),
        item.get("output").map(output_text).unwrap_or_default(),
    )
}

/// The text of one `reasoning` item: its summary, or else its content.
pub(super) fn reasoning_text(item: &Value) -> Option<String> {
    reasoning_parts(item).map(|parts| {
        parts
            .into_iter()
            .map(|(_, text)| text)
            .collect::<Vec<_>>()
            .join("\n")
    })
}

/// The non-empty text parts of a `reasoning` item's summary, or else of its
/// content, by their index.
pub(super) fn reasoning_parts(item: &Value) -> Option<Vec<(u64, &str)>> {
    ["summary", "content"].iter().find_map(|key| {
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

impl CallSlot {
    /// Reconciles the call with one `*_call` item snapshot.
    pub(super) fn reconcile(&mut self, item: &Value) {
        let field = |key| Projection::field(item, key);
        self.call_id = field("call_id").or_else(|| self.call_id.take());
        self.name = field("name").or_else(|| self.name.take());
        let input = call_input(item);
        if !input.is_empty() {
            self.input = input;
        }
    }
}

/// Applies one `response.*` stream event; returns whether `value` was one.
pub(super) fn apply_event(slots: &mut BTreeMap<u64, OutputSlot>, value: &Value) -> bool {
    let output_index = value["output_index"].as_u64().unwrap_or(0);
    let part_index = value
        .get("content_index")
        .or_else(|| value.get("summary_index"))
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let text_slot = |kind: &str| {
        OutputSlot::new(if kind.starts_with("response.reasoning") {
            SlotBody::reasoning()
        } else {
            SlotBody::message()
        })
    };
    match value["type"].as_str().unwrap_or_default() {
        kind @ ("response.output_text.delta" | "response.reasoning_summary_text.delta") => {
            if let Some(delta) = value["delta"].as_str()
                && let Some(part) = slots
                    .entry(output_index)
                    .or_insert_with(|| text_slot(kind))
                    .text_part(part_index)
            {
                part.push_str(delta);
            }
        }
        kind @ ("response.output_text.done" | "response.reasoning_summary_text.done") => {
            if let Some(text) = value["text"].as_str() {
                slots
                    .entry(output_index)
                    .or_insert_with(|| text_slot(kind))
                    .reconcile(part_index, text);
            }
        }
        kind @ ("response.content_part.done" | "response.reasoning_summary_part.done") => {
            if let Some(text) = value.get("part").and_then(response_part_text) {
                slots
                    .entry(output_index)
                    .or_insert_with(|| text_slot(kind))
                    .reconcile(part_index, text);
            }
        }
        "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta" => {
            if let Some(delta) = value["delta"].as_str()
                && let SlotBody::ToolCall(call) = &mut slots
                    .entry(output_index)
                    .or_insert_with(|| OutputSlot::new(SlotBody::ToolCall(CallSlot::default())))
                    .body
            {
                call.streamed.push_str(delta);
            }
        }
        "response.output_item.added" | "response.output_item.done" => {
            if let Some(item) = value.get("item") {
                reconcile_output_item(slots, output_index, item);
            }
        }
        "response.completed" | "response.done" => {
            if let Some(output) = value.pointer("/response/output").and_then(Value::as_array) {
                apply_output(slots, output);
            }
        }
        _ => return false,
    }
    true
}

/// Reconciles every item of an `output` array.
pub(super) fn apply_output(slots: &mut BTreeMap<u64, OutputSlot>, output: &[Value]) {
    for (index, item) in output.iter().enumerate() {
        reconcile_output_item(slots, slot_index(index), item);
    }
}

/// Reconciles one output item, which carries its `id`.
fn reconcile_output_item(slots: &mut BTreeMap<u64, OutputSlot>, index: u64, item: &Value) {
    let slot = OpenAiResponse::reconcile_item(slots, index, item);
    slot.item_id = Projection::field(item, "id").or_else(|| slot.item_id.take());
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::event::ContentCompleteness;
    use serde_json::json;

    use super::super::tests::{item_ids, summary};
    use super::*;

    #[test]
    fn request_entries_carry_the_id_of_their_responses_item() {
        let conversation = OpenAiRequest::parse(
            Some(&json!({"input":[
                {"type":"message","id":"msg_dev","role":"developer","content":[
                    {"type":"input_text","text":"one"},{"type":"input_text","text":"two"}
                ]},
                {"role":"user","content":"unidentified"},
                {"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAAA"},
                {"type":"function_call","id":"fc_1","call_id":"call_1","name":"exec","arguments":"{}"},
                {"type":"function_call_output","id":"fco_1","call_id":"call_1","output":"ok"},
                "plain"
            ]})),
            false,
        )
        .conversation();

        assert_eq!(
            summary(&conversation),
            [
                (EntryRole::Developer, "one", None, None),
                (EntryRole::Developer, "two", None, None),
                (EntryRole::User, "unidentified", None, None),
                (EntryRole::Reasoning, "", None, None),
                (EntryRole::ToolCall, "{}", Some("call_1"), Some("exec")),
                (EntryRole::ToolResult, "ok", Some("call_1"), None),
                (EntryRole::User, "plain", None, None),
            ]
        );
        assert_eq!(
            item_ids(&conversation),
            [
                Some("msg_dev"),
                Some("msg_dev"),
                None,
                Some("rs_1"),
                Some("fc_1"),
                Some("fco_1"),
                None
            ]
        );
    }

    #[test]
    fn output_entries_carry_the_id_of_their_item() {
        let reasoning =
            json!({"type":"reasoning","id":"rs_1","summary":[],"encrypted_content":"gAAAA"});
        let message = json!({"type":"message","id":"msg_1","role":"assistant","content":[
            {"type":"output_text","text":"first"},{"type":"output_text","text":"second"}
        ]});
        let values = vec![
            json!({"type":"response.output_item.added","output_index":0_i32,"item":reasoning}),
            json!({"type":"response.output_item.done","output_index":0_i32,"item":reasoning}),
            json!({"type":"response.output_item.added","output_index":1_i32,"item":{"type":"message","id":"msg_1","role":"assistant","content":[]}}),
            json!({"type":"response.output_text.delta","item_id":"msg_1","output_index":1_i32,"content_index":0_i32,"delta":"first"}),
            json!({"type":"response.output_text.delta","item_id":"msg_1","output_index":1_i32,"content_index":1_i32,"delta":"second"}),
            json!({"type":"response.completed","response":{"id":"resp_1","output":[reasoning, message]}}),
        ];
        let streamed = OpenAiResponse::assemble(&values, false).conversation();
        let whole = OpenAiResponse::assemble(
            &[json!({"id":"resp_1","output":[reasoning, message]})],
            false,
        )
        .conversation();

        // A reasoning item without readable text still yields its entry.
        assert_eq!(
            summary(&streamed),
            [
                (EntryRole::Reasoning, "", None, None),
                (EntryRole::Assistant, "first", None, None),
                (EntryRole::Assistant, "second", None, None),
            ]
        );
        assert_eq!(
            item_ids(&streamed),
            [Some("rs_1"), Some("msg_1"), Some("msg_1")]
        );
        assert_eq!(streamed.entries, whole.entries);
    }

    #[test]
    fn a_replayed_output_item_keeps_the_id_its_response_gave_it() {
        // The ids and item shapes of a captured Codex turn whose commentary
        // and tool call come back in the next request.
        let message = json!({"type":"message","id":"msg_05ddafa48ca28316016ad09e37fb7c819abc6fd9aad3939596","role":"assistant","content":[{"type":"output_text","text":"I will check the size."}],"phase":"commentary"});
        let call = json!({"type":"custom_tool_call","id":"ctc_05ddafa48ca28316016ad09e382a34819aaef0cbe1ee246e62","status":"completed","call_id":"call_281a8bc325b04e1c83d3701fbb2890d4","name":"exec","input":"wc -c notes.txt"});
        let response = OpenAiResponse::assemble(
            &[
                json!({"type":"response.output_item.added","output_index":0_i32,"item":{"type":"message","id":"msg_05ddafa48ca28316016ad09e37fb7c819abc6fd9aad3939596","role":"assistant","status":"in_progress","content":[]}}),
                json!({"type":"response.output_text.delta","item_id":"msg_05ddafa48ca28316016ad09e37fb7c819abc6fd9aad3939596","output_index":0_i32,"content_index":0_i32,"delta":"I will check "}),
                json!({"type":"response.output_text.delta","item_id":"msg_05ddafa48ca28316016ad09e37fb7c819abc6fd9aad3939596","output_index":0_i32,"content_index":0_i32,"delta":"the size."}),
                json!({"type":"response.output_item.done","output_index":0_i32,"item":message}),
                json!({"type":"response.output_item.added","output_index":1_i32,"item":{"type":"custom_tool_call","id":"ctc_05ddafa48ca28316016ad09e382a34819aaef0cbe1ee246e62","status":"in_progress","call_id":"call_281a8bc325b04e1c83d3701fbb2890d4","name":"exec","input":""}}),
                json!({"type":"response.custom_tool_call_input.delta","item_id":"ctc_05ddafa48ca28316016ad09e382a34819aaef0cbe1ee246e62","output_index":1_i32,"delta":"wc -c notes.txt"}),
                json!({"type":"response.output_item.done","output_index":1_i32,"item":call}),
                json!({"type":"response.completed","response":{"id":"resp_1","output":[message, call]}}),
            ],
            false,
        )
        .conversation();
        let request = OpenAiRequest::parse(
            Some(&json!({"input":[
                {"type":"message","id":"msg_01a13ee9-f8c3-7e70-b66f-6c6feeeb1bea","role":"user","content":[{"type":"input_text","text":"How big is notes.txt?"}]},
                message,
                call,
                {"type":"custom_tool_call_output","id":"ctco_01a13eea-0daa-7550-89f4-3ef8f89939a1","call_id":"call_281a8bc325b04e1c83d3701fbb2890d4","output":[{"type":"input_text","text":"11 notes.txt"}]}
            ]})),
            false,
        )
        .conversation();

        assert_eq!(
            item_ids(&response),
            [
                Some("msg_05ddafa48ca28316016ad09e37fb7c819abc6fd9aad3939596"),
                Some("ctc_05ddafa48ca28316016ad09e382a34819aaef0cbe1ee246e62"),
            ]
        );
        assert_eq!(request.entries[1..3], response.entries[..]);
    }

    #[test]
    fn final_items_replace_deltas_without_repeating_entries() {
        let values = vec![
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"hel"}),
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"lo"}),
            json!({"type":"response.output_item.done","output_index":1_i32,"item":{"id":"m1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}}),
            json!({"type":"response.completed","response":{"output":[
                {"id":"reason","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}],"content":null},
                {"id":"m1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}
            ]}}),
        ];
        let response = OpenAiResponse::assemble(&values, false);

        assert_eq!(
            summary(&response.conversation()),
            [
                (EntryRole::Reasoning, "thinking", None, None),
                (EntryRole::Assistant, "hello", None, None),
            ]
        );
    }

    #[test]
    fn unfinished_parallel_parts_keep_order_and_identical_text() {
        let values = vec![
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"same"}),
            json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":1_i32,"delta":"same"}),
            json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":0_i32,"delta":"first"}),
        ];
        let conversation = OpenAiResponse::assemble(&values, true).conversation();

        assert_eq!(
            summary(&conversation),
            [
                (EntryRole::Assistant, "first", None, None),
                (EntryRole::Assistant, "same", None, None),
                (EntryRole::Assistant, "same", None, None),
            ]
        );
        assert_eq!(conversation.completeness, ContentCompleteness::Partial);
    }

    #[test]
    fn streamed_tool_calls_become_tool_call_entries() {
        let call = r#"{"type":"function_call","id":"fc_1","call_id":"call_1","name":"exec_command","arguments":"{\"cmd\": \"pwd\"}"}"#;
        let item: Value = serde_json::from_str(call).unwrap();
        let values = vec![
            json!({"type":"response.output_item.added","output_index":0_i32,"item":{"type":"function_call","id":"fc_1","call_id":"call_1","name":"exec_command","arguments":""}}),
            json!({"type":"response.function_call_arguments.delta","output_index":0_i32,"delta":"{\"cmd\": "}),
            json!({"type":"response.function_call_arguments.delta","output_index":0_i32,"delta":"\"pwd\"}"}),
            json!({"type":"response.output_item.added","output_index":1_i32,"item":{"type":"custom_tool_call","call_id":"call_2","name":"apply_patch","input":""}}),
            json!({"type":"response.custom_tool_call_input.delta","output_index":1_i32,"delta":"*** Begin Patch"}),
            json!({"type":"response.output_item.done","output_index":0_i32,"item":item}),
        ];
        let response = OpenAiResponse::assemble(&values, false);

        assert_eq!(
            summary(&response.conversation()),
            [
                (
                    EntryRole::ToolCall,
                    "{\"cmd\": \"pwd\"}",
                    Some("call_1"),
                    Some("exec_command")
                ),
                (
                    EntryRole::ToolCall,
                    "*** Begin Patch",
                    Some("call_2"),
                    Some("apply_patch")
                ),
            ]
        );
    }

    #[test]
    fn request_follows_the_item_table() {
        let request = OpenAiRequest::parse(
            Some(&json!({
                "instructions":"rules", "previous_response_id":"r1",
                "input":[
                    {"type":"additional_tools","role":"developer","tools":[{"name":"x"}]},
                    {"type":"message","role":"developer","content":[
                        {"type":"input_text","text":"one"},{"type":"input_text","text":"two"}
                    ]},
                    {"role":"user","content":[
                        {"type":"input_text","text":"hello","future":42_i32},
                        {"type":"input_image","image_url":"data:image/png;base64,AA=="}
                    ]},
                    {"role":"user","content":"hello"},
                    {"type":"reasoning","summary":[{"type":"summary_text","text":"plan"}],"encrypted_content":"x"},
                    {"type":"custom_tool_call","call_id":"c1","name":"exec","input":"ls -la"},
                    {"type":"custom_tool_call_output","call_id":"c1","output":"total 0"},
                    {"type":"function_call","call_id":"c2","name":"read","arguments":"{\"b\":1,\"a\":2}"},
                    {"type":"function_call_output","call_id":"c2","output":[{"type":"input_text","text":"file"}]},
                    {"type":"web_search_call","id":"ws_1","action":{"type":"search","query":"q"}},
                    {"type":"agent_message","content":"from a subagent"},
                    {"content":"role unavailable"}
                ]
            })),
            false,
        );

        assert_eq!(
            summary(&request.conversation()),
            [
                (EntryRole::System, "rules", None, None),
                (EntryRole::Developer, "one", None, None),
                (EntryRole::Developer, "two", None, None),
                (EntryRole::User, "hello", None, None),
                (EntryRole::User, "hello", None, None),
                (EntryRole::Reasoning, "plan", None, None),
                (EntryRole::ToolCall, "ls -la", Some("c1"), Some("exec")),
                (EntryRole::ToolResult, "total 0", Some("c1"), None),
                (
                    EntryRole::ToolCall,
                    "{\"b\":1,\"a\":2}",
                    Some("c2"),
                    Some("read")
                ),
                (EntryRole::ToolResult, "file", Some("c2"), None),
                (
                    EntryRole::ToolCall,
                    "{\"type\":\"search\",\"query\":\"q\"}",
                    None,
                    None
                ),
                (EntryRole::Unknown, "from a subagent", None, None),
                (EntryRole::Unknown, "role unavailable", None, None),
            ]
        );
    }

    #[test]
    fn entries_follow_the_output_items() {
        let values = vec![
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"hel"}),
            json!({"type":"response.completed","response":{"output":[
                {"id":"reason","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
                {"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]},
                {"id":"fc_1","type":"function_call","call_id":"call_1","name":"exec","arguments":"{\"cmd\":\"pwd\"}"}
            ]}}),
        ];
        let response = OpenAiResponse::assemble(&values, false);

        assert_eq!(
            summary(&response.conversation()),
            [
                (EntryRole::Reasoning, "thinking", None, None),
                (EntryRole::Assistant, "hello", None, None),
                (
                    EntryRole::ToolCall,
                    "{\"cmd\":\"pwd\"}",
                    Some("call_1"),
                    Some("exec")
                ),
            ]
        );
    }
}
