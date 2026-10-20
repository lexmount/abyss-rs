//! Conversation projection regression cases.

use abyss_plugin_protocol::event::{ContentCompleteness, MessageRole};
use serde_json::json;

use super::response::ChatResponse;
use crate::protocol::model::tool::ParsedToolEvent;

#[test]
fn chat_choices_are_independent_and_final_message_is_authoritative() {
    let values = vec![
        json!({"choices":[{"index":0_i32,"delta":{"content":"hel"}},{"index":1_i32,"delta":{"content":"other"}}]}),
        json!({"choices":[{"index":0_i32,"delta":{"content":"lo"}}]}),
        json!({"choices":[{"index":0_i32,"message":{"role":"assistant","content":"corrected"}}]}),
    ];
    let conversation = ChatResponse::assemble(&values, false).conversation();

    assert_eq!(conversation.messages[0].text, "corrected");
    assert_eq!(conversation.messages[1].text, "other");
}

#[test]
fn chat_tool_snapshot_replaces_streamed_arguments_without_duplicate_calls() {
    let values = vec![
        json!({"choices":[{"index":0_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":\"wrong\"}"}}]}}]}),
        json!({"choices":[{"index":0_i32,"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":\"correct\"}"}}]}}]}),
    ];
    let response = ChatResponse::assemble(&values, false);
    assert_eq!(
        response.tool_calls(),
        vec![ParsedToolEvent::ToolCall {
            item_id: None,
            call_id: Some("c1".into()),
            name: Some("read".into()),
            input: r#"{"path":"correct"}"#.into(),
        }]
    );
    assert_eq!(response.texts(), Vec::<String>::new());
}

#[test]
fn chat_truncated_arguments_stay_partial_without_inventing_json() {
    let response = ChatResponse::assemble(
        &[
            json!({"choices":[{"index":0_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":"}}]}}]}),
        ],
        true,
    );
    assert_eq!(
        response.conversation().completeness,
        ContentCompleteness::Partial
    );
    assert_eq!(
        response.tool_calls(),
        vec![ParsedToolEvent::ToolCall {
            item_id: None,
            call_id: Some("c1".into()),
            name: Some("read".into()),
            input: r#"{"path":"#.into(),
        }]
    );
}

#[test]
fn compatible_thinking_is_assembled_per_choice_and_reconciled_with_snapshots() {
    let response = ChatResponse::assemble(
        &[
            json!({"choices":[
                {"index":0_i32,"delta":{"reasoning_content":"partial "}},
                {"index":1_i32,"delta":{"reasoning_content":"other","content":"second answer"}}
            ]}),
            json!({"choices":[{"index":0_i32,"delta":{"reasoning_content":"thought","content":"answer"}}]}),
            json!({"choices":[{"index":0_i32,"message":{"role":"assistant","reasoning_content":"correct thought","content":"answer"}}]}),
        ],
        false,
    );
    let messages = response.conversation().messages;
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0].role, MessageRole::Reasoning);
    assert_eq!(messages[0].text, "correct thought");
    assert_eq!(messages[1].text, "answer");
    assert_eq!(messages[2].role, MessageRole::Reasoning);
    assert_eq!(messages[2].text, "other");
    assert_eq!(messages[3].text, "second answer");
}

#[test]
fn incomplete_thinking_keeps_partial_status_and_null_thinking_adds_no_message() {
    let response = ChatResponse::assemble(
        &[json!({"choices":[{"index":0_i32,"delta":{"reasoning_content":"unfinished"}}]})],
        true,
    );
    assert_eq!(
        response.conversation().completeness,
        ContentCompleteness::Partial
    );
    assert_eq!(response.conversation().messages[0].text, "unfinished");
    let response = ChatResponse::assemble(
        &[
            json!({"choices":[{"index":0_i32,"message":{"role":"assistant","reasoning_content":null,"content":"answer"}}]}),
        ],
        false,
    );
    assert_eq!(response.conversation().messages.len(), 1);
    assert_eq!(
        response.conversation().messages[0].role,
        MessageRole::Assistant
    );
}
