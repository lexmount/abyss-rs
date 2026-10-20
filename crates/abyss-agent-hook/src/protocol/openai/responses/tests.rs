//! Conversation projection regression cases.

use abyss_plugin_protocol::event::{ContentCompleteness, MessageRole};
use serde_json::json;

use super::{request::ResponsesRequest, response::ResponsesResponse};

#[test]
fn final_items_replace_deltas_without_repeating_messages() {
    let values = vec![
        json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"hel"}),
        json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"lo"}),
        json!({"type":"response.output_item.done","output_index":1_i32,"item":{"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]}}),
        json!({"type":"response.completed","response":{"output":[
            {"id":"reason","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
            {"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]}
        ]}}),
    ];
    let response = ResponsesResponse::assemble(&values, false);
    let conversation = response.conversation();

    assert_eq!(conversation.messages.len(), 2);
    assert_eq!(conversation.messages[0].role, MessageRole::Reasoning);
    assert_eq!(conversation.messages[0].id.as_deref(), Some("reason"));
    assert_eq!(conversation.messages[0].text, "thinking");
    assert_eq!(conversation.messages[1].id.as_deref(), Some("m1"));
    assert_eq!(conversation.messages[1].text, "hello");
    assert_eq!(response.texts(), vec!["thinking", "hello"]);
}

#[test]
fn unfinished_parallel_blocks_keep_order_and_identical_text() {
    let values = vec![
        json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"same"}),
        json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":1_i32,"delta":"same"}),
        json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":0_i32,"delta":"first"}),
    ];
    let conversation = ResponsesResponse::assemble(&values, true).conversation();

    assert_eq!(conversation.messages.len(), 2);
    assert_eq!(conversation.messages[0].text, "first\nsame");
    assert_eq!(conversation.messages[1].text, "same");
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
        let response = ResponsesResponse::assemble(events, partial);
        let conversation = response.conversation();
        assert_eq!(conversation.messages.len(), 1);
        assert_eq!(conversation.messages[0].role, MessageRole::Reasoning);
        assert_eq!(conversation.messages[0].text, "Read the file.");
        assert_eq!(
            conversation.completeness,
            if partial {
                ContentCompleteness::Partial
            } else {
                ContentCompleteness::Complete
            }
        );
    }

    let request = ResponsesRequest::parse(Some(&json!({"input":[item]})), false);
    let conversation = request.conversation();
    assert_eq!(conversation.messages[0].role, MessageRole::Reasoning);
    assert_eq!(conversation.messages[0].id.as_deref(), Some("reason-glm"));
    assert_eq!(conversation.messages[0].text, "Read the file.");
}

#[test]
fn request_preserves_roles_and_repeated_messages() {
    let request = ResponsesRequest::parse(
        Some(&json!({
            "instructions":"", "previous_response_id":"r1",
            "input":[{"role":"developer","content":"rules"},
                {"role":"user","content":[{"type":"input_text","text":"hello","future":42_i32}]},
                {"role":"user","content":"hello"},
                {"type":"function_call_output","call_id":"c1","output":"secret"},
                {"content":"role unavailable"}]
        })),
        false,
    );
    let conversation = request.conversation();

    assert!(conversation.instructions_present);
    let roles = conversation
        .messages
        .iter()
        .map(|message| message.role)
        .collect::<Vec<_>>();
    assert_eq!(
        roles,
        vec![
            MessageRole::Developer,
            MessageRole::Developer,
            MessageRole::User,
            MessageRole::User,
            MessageRole::Tool,
            MessageRole::Unknown,
        ]
    );
    assert_eq!(conversation.messages[2].text, conversation.messages[3].text);
    assert_eq!(conversation.messages[4].text, "");
    assert_eq!(
        request.texts(),
        vec!["rules\nhello\nhello\nrole unavailable"]
    );
}

#[test]
fn request_text_excludes_tool_results_and_images() {
    let request = ResponsesRequest::parse(
        Some(&json!({"input":[{"role":"user","content":[
            {"type":"input_text","text":"visible"},
            {"type":"tool_result","content":"tool secret"},
            {"type":"input_image","image_url":"image secret"}
        ]}]})),
        false,
    );

    assert_eq!(request.conversation().messages[0].text, "visible");
    assert_eq!(request.texts(), vec!["visible"]);
}
