//! Conversation projection regression cases.

use abyss_plugin_protocol::event::ContentCompleteness;
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
