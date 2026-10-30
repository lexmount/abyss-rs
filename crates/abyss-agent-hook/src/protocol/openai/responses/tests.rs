//! Conversation projection regression cases.

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, EntryRole};
use serde_json::{Value, json};

use super::{request::ResponsesRequest, response::ResponsesResponse};
use crate::protocol::model::conversation::role_texts;

fn assemble(values: &[Value], incomplete: bool) -> Conversation {
    ResponsesResponse::assemble(values, incomplete).conversation()
}

fn summary(conversation: &Conversation) -> Vec<(EntryRole, &str, Option<&str>, Option<&str>)> {
    conversation
        .entries
        .iter()
        .map(|entry| {
            (
                entry.role,
                entry.text.as_str(),
                entry.call_id.as_deref(),
                entry.name.as_deref(),
            )
        })
        .collect()
}

fn item_ids(conversation: &Conversation) -> Vec<Option<&str>> {
    conversation
        .entries
        .iter()
        .map(|entry| entry.item_id.as_deref())
        .collect()
}

#[test]
fn final_items_replace_deltas_without_repeating_entries() {
    let values = vec![
        json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"hel"}),
        json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"lo"}),
        json!({"type":"response.output_item.done","output_index":1_i32,"item":{"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]}}),
        json!({"type":"response.completed","response":{"output":[
            {"id":"reason","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
            {"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]}
        ]}}),
    ];
    let conversation = assemble(&values, false);

    assert_eq!(
        role_texts(&conversation),
        [
            (EntryRole::Reasoning, "thinking"),
            (EntryRole::Assistant, "hello")
        ]
    );
    assert_eq!(item_ids(&conversation), [Some("reason"), Some("m1")]);
}

#[test]
fn unfinished_parallel_parts_keep_order_and_identical_text() {
    let values = vec![
        json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"same"}),
        json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":1_i32,"delta":"same"}),
        json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":0_i32,"delta":"first"}),
    ];
    let conversation = assemble(&values, true);

    assert_eq!(
        role_texts(&conversation),
        [
            (EntryRole::Assistant, "first"),
            (EntryRole::Assistant, "same"),
            (EntryRole::Assistant, "same")
        ]
    );
    assert_eq!(conversation.completeness, ContentCompleteness::Partial);
}

#[test]
fn reasoning_text_deltas_and_snapshots_preserve_content_without_duplicates() {
    let item = json!({
        "id":"reason-glm", "type":"reasoning", "summary":[],
        "encrypted_content":"must not become visible",
        "content":[{"type":"reasoning_text","text":"Read the file."}]
    });
    let values = [
        json!({"type":"response.reasoning_text.delta","output_index":0_i32,"content_index":0_i32,"delta":"Read "}),
        json!({"type":"response.reasoning_text.delta","output_index":0_i32,"content_index":0_i32,"delta":"the file."}),
        json!({"type":"response.reasoning_text.done","output_index":0_i32,"content_index":0_i32,"text":"Read the file."}),
        json!({"type":"response.content_part.done","output_index":0_i32,"content_index":0_i32,"part":item["content"][0]}),
        json!({"type":"response.output_item.done","output_index":0_i32,"item":item}),
        json!({"type":"response.completed","response":{"output":[item]}}),
    ];
    // Exercise accumulation, done-only reconciliation, final snapshots and JSON separately.
    for (events, partial) in [
        (&values[..2], true),
        (&values[2..3], true),
        (&values[..], false),
        (&values[5..], false),
        (&[json!({"output":[item]})][..], false),
    ] {
        let conversation = assemble(events, partial);
        assert_eq!(
            role_texts(&conversation),
            [(EntryRole::Reasoning, "Read the file.")]
        );
        assert_eq!(
            conversation.completeness,
            if partial {
                ContentCompleteness::Partial
            } else {
                ContentCompleteness::Complete
            }
        );
    }

    let conversation =
        ResponsesRequest::parse(Some(&json!({"input":[item]})), false).conversation();
    assert_eq!(
        role_texts(&conversation),
        [(EntryRole::Reasoning, "Read the file.")]
    );
    assert_eq!(item_ids(&conversation), [Some("reason-glm")]);
}

#[test]
fn request_preserves_roles_and_repeated_messages() {
    let conversation = ResponsesRequest::parse(
        Some(&json!({
            "instructions":"", "previous_response_id":"r1",
            "input":[{"role":"developer","content":"rules"},
                {"role":"user","content":[{"type":"input_text","text":"hello","future":42_i32}]},
                {"role":"user","content":"hello"},
                {"type":"function_call_output","call_id":"c1","output":"secret"},
                {"content":"role unavailable"}]
        })),
        false,
    )
    .conversation();

    assert_eq!(
        role_texts(&conversation),
        [
            (EntryRole::Developer, ""),
            (EntryRole::Developer, "rules"),
            (EntryRole::User, "hello"),
            (EntryRole::User, "hello"),
            (EntryRole::ToolResult, "secret"),
            (EntryRole::Unknown, "role unavailable"),
        ]
    );
}

#[test]
fn request_parts_follow_the_part_table() {
    let conversation = ResponsesRequest::parse(
        Some(&json!({"input":[{"role":"user","content":[
            {"type":"input_text","text":"visible"},
            {"type":"tool_result","content":"tool output"},
            {"type":"input_image","image_url":"image secret"}
        ]}]})),
        false,
    )
    .conversation();

    // A tool part contributes nothing; an image part has no text.
    assert_eq!(role_texts(&conversation), [(EntryRole::User, "visible")]);
}

#[test]
fn request_entries_carry_the_id_of_their_responses_item() {
    let conversation = ResponsesRequest::parse(
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
    let streamed = ResponsesResponse::assemble(&values, false).conversation();
    let whole = ResponsesResponse::assemble(
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
    // Codex-shaped ids and items of a turn whose commentary and tool call
    // come back in the next request.
    let message = json!({"type":"message","id":"msg_0000000000000000000000000000000000000000000000a001","role":"assistant","content":[{"type":"output_text","text":"I will check the size."}],"phase":"commentary"});
    let call = json!({"type":"custom_tool_call","id":"ctc_0000000000000000000000000000000000000000000000c001","status":"completed","call_id":"call_00000000000000000000000000000001","name":"exec","input":"wc -c notes.txt"});
    let response = ResponsesResponse::assemble(&[
            json!({"type":"response.output_item.added","output_index":0_i32,"item":{"type":"message","id":"msg_0000000000000000000000000000000000000000000000a001","role":"assistant","status":"in_progress","content":[]}}),
            json!({"type":"response.output_text.delta","item_id":"msg_0000000000000000000000000000000000000000000000a001","output_index":0_i32,"content_index":0_i32,"delta":"I will check "}),
            json!({"type":"response.output_text.delta","item_id":"msg_0000000000000000000000000000000000000000000000a001","output_index":0_i32,"content_index":0_i32,"delta":"the size."}),
            json!({"type":"response.output_item.done","output_index":0_i32,"item":message}),
            json!({"type":"response.output_item.added","output_index":1_i32,"item":{"type":"custom_tool_call","id":"ctc_0000000000000000000000000000000000000000000000c001","status":"in_progress","call_id":"call_00000000000000000000000000000001","name":"exec","input":""}}),
            json!({"type":"response.custom_tool_call_input.delta","item_id":"ctc_0000000000000000000000000000000000000000000000c001","output_index":1_i32,"delta":"wc -c notes.txt"}),
            json!({"type":"response.output_item.done","output_index":1_i32,"item":call}),
            json!({"type":"response.completed","response":{"id":"resp_1","output":[message, call]}}),
        ],
        false,
    )
    .conversation();
    let request = ResponsesRequest::parse(Some(&json!({"input":[
            {"type":"message","id":"msg_00000000-0000-7000-8000-000000000001","role":"user","content":[{"type":"input_text","text":"How big is notes.txt?"}]},
            message,
            call,
            {"type":"custom_tool_call_output","id":"ctco_00000000-0000-7000-8000-000000000002","call_id":"call_00000000000000000000000000000001","output":[{"type":"input_text","text":"11 notes.txt"}]}
        ]})),
        false,
    )
    .conversation();

    assert_eq!(
        item_ids(&response),
        [
            Some("msg_0000000000000000000000000000000000000000000000a001"),
            Some("ctc_0000000000000000000000000000000000000000000000c001"),
        ]
    );
    assert_eq!(request.entries[1..3], response.entries[..]);
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
    let response = ResponsesResponse::assemble(&values, false);

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
    let request = ResponsesRequest::parse(
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
            (EntryRole::Developer, "rules", None, None),
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
    let response = ResponsesResponse::assemble(&values, false);

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

#[test]
fn message_items_are_read_only_through_responses_fields() {
    // Chat Completions message fields mean nothing on a Responses item.
    let conversation = ResponsesRequest::parse(
        Some(&json!({"input":[{"type":"message","role":"assistant",
            "content":[{"type":"output_text","text":"answer"}],
            "reasoning_content":"chat thinking", "refusal":"chat refusal",
            "tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{}"}}]
        }]})),
        false,
    )
    .conversation();

    assert_eq!(
        role_texts(&conversation),
        [(EntryRole::Assistant, "answer")]
    );
}

#[test]
fn reasoning_reads_its_content_before_its_summary() {
    let item = json!({"id":"rs_1","type":"reasoning",
        "summary":[{"type":"summary_text","text":"summary"}],
        "content":[{"type":"reasoning_text","text":"full reasoning"}]});
    let summary_only = json!({"id":"rs_2","type":"reasoning",
        "summary":[{"type":"summary_text","text":"summary"}],"content":null});

    assert_eq!(
        role_texts(&assemble(&[json!({"output":[item, summary_only]})], false)),
        [
            (EntryRole::Reasoning, "full reasoning"),
            (EntryRole::Reasoning, "summary")
        ]
    );
    assert_eq!(
        role_texts(&ResponsesRequest::parse(Some(&json!({"input":[item]})), false).conversation()),
        [(EntryRole::Reasoning, "full reasoning")]
    );
}

#[test]
fn unrecognized_output_items_keep_their_text_in_their_role() {
    let conversation = assemble(
        &[
            json!({"output":[{"type":"future_item","id":"f1","role":"assistant",
            "content":[{"type":"output_text","text":"future"}]}]}),
        ],
        false,
    );

    assert_eq!(
        role_texts(&conversation),
        [(EntryRole::Assistant, "future")]
    );
}
