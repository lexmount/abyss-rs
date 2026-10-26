//! Conversation projection regression cases.

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, EntryRole};
use serde_json::{Value, json};

use super::{request::ChatRequest, response::ChatResponse};
use crate::protocol::model::conversation::role_texts;

fn assemble(values: &[Value], incomplete: bool) -> Conversation {
    ChatResponse::assemble(values, incomplete).conversation()
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

/// The text, call id, and tool name of every tool-call entry.
fn calls(conversation: &Conversation) -> Vec<(&str, Option<&str>, Option<&str>)> {
    conversation
        .entries
        .iter()
        .filter(|entry| entry.role == EntryRole::ToolCall)
        .map(|entry| {
            (
                entry.text.as_str(),
                entry.call_id.as_deref(),
                entry.name.as_deref(),
            )
        })
        .collect()
}

#[test]
fn empty_tool_metadata_in_later_deltas_preserves_call_identity() {
    for (kind, input_key) in [("function", "arguments"), ("custom", "input")] {
        let conversation = assemble(
            &[
                json!({"choices":[{"delta":{"tool_calls":[{"index":0_i32,"id":"c1","type":kind,
                    kind:{"name":"read",input_key:"first"}}]}}]}),
                json!({"choices":[{"delta":{"tool_calls":[{"index":0_i32,"id":"","type":kind,
                    kind:{"name":"",input_key:" second"}}]}}]}),
                json!({"choices":[{"delta":{"tool_calls":[{"index":0_i32,"id":null,
                    kind:{input_key:""}}]}}]}),
            ],
            false,
        );
        assert_eq!(
            calls(&conversation),
            [("first second", Some("c1"), Some("read"))]
        );
    }
}

#[test]
fn chat_choices_are_independent_and_final_message_is_authoritative() {
    let values = vec![
        json!({"choices":[{"index":0_i32,"delta":{"content":"hel"}},{"index":1_i32,"delta":{"content":"other"}}]}),
        json!({"choices":[{"index":0_i32,"delta":{"content":"lo"}}]}),
        json!({"choices":[{"index":0_i32,"message":{"role":"assistant","content":"corrected"}}]}),
    ];

    assert_eq!(
        role_texts(&assemble(&values, false)),
        [
            (EntryRole::Assistant, "corrected"),
            (EntryRole::Assistant, "other")
        ]
    );
}

#[test]
fn chat_tool_snapshot_replaces_streamed_arguments_without_duplicate_calls() {
    let values = vec![
        json!({"choices":[{"index":0_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":\"wrong\"}"}}]}}]}),
        json!({"choices":[{"index":0_i32,"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":\"correct\"}"}}]}}]}),
    ];

    assert_eq!(
        role_texts(&assemble(&values, false)),
        [(EntryRole::ToolCall, r#"{"path":"correct"}"#)]
    );
}

#[test]
fn chat_truncated_arguments_stay_partial_without_inventing_json() {
    let conversation = assemble(
        &[
            json!({"choices":[{"index":0_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"c1","type":"function","function":{"name":"read","arguments":"{\"path\":"}}]}}]}),
        ],
        true,
    );
    assert_eq!(conversation.completeness, ContentCompleteness::Partial);
    assert_eq!(
        calls(&conversation),
        [(r#"{"path":"#, Some("c1"), Some("read"))]
    );
}

#[test]
fn compatible_thinking_is_assembled_per_choice_and_reconciled_with_snapshots() {
    let conversation = assemble(
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
    assert_eq!(
        role_texts(&conversation),
        [
            (EntryRole::Reasoning, "correct thought"),
            (EntryRole::Assistant, "answer"),
            (EntryRole::Reasoning, "other"),
            (EntryRole::Assistant, "second answer"),
        ]
    );
}

#[test]
fn incomplete_thinking_keeps_partial_status_and_null_thinking_adds_no_entry() {
    let conversation = assemble(
        &[json!({"choices":[{"index":0_i32,"delta":{"reasoning_content":"unfinished"}}]})],
        true,
    );
    assert_eq!(conversation.completeness, ContentCompleteness::Partial);
    assert_eq!(
        role_texts(&conversation),
        [(EntryRole::Reasoning, "unfinished")]
    );
    let conversation = assemble(
        &[
            json!({"choices":[{"index":0_i32,"message":{"role":"assistant","reasoning_content":null,"content":"answer"}}]}),
        ],
        false,
    );
    assert_eq!(
        role_texts(&conversation),
        [(EntryRole::Assistant, "answer")]
    );
}

#[test]
fn chat_choices_are_independent_and_carry_their_tool_calls() {
    let values = vec![
        json!({"choices":[{"index":0_i32,"delta":{"content":"hel"}},{"index":1_i32,"delta":{"content":"other"}}]}),
        json!({"choices":[{"index":0_i32,"delta":{"content":"lo"}}]}),
        json!({"choices":[{"index":1_i32,"delta":{"tool_calls":[{"index":0_i32,"id":"call_9","function":{"name":"lookup","arguments":"{\"q\":"}}]}}]}),
        json!({"choices":[{"index":1_i32,"delta":{"tool_calls":[{"index":0_i32,"function":{"arguments":"1}"}}]}}]}),
        json!({"id":"chatcmpl-1","choices":[{"index":0_i32,"message":{"role":"assistant","content":"corrected"}}]}),
    ];
    let conversation = ChatResponse::assemble(&values, false).conversation();
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
    let request = ChatRequest::parse(
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

#[test]
fn refusals_are_kept_and_empty_opening_deltas_add_no_entry() {
    let streamed = assemble(
        &[
            json!({"choices":[{"index":0_i32,"delta":{"role":"assistant","content":""}}]}),
            json!({"choices":[{"index":0_i32,"delta":{"refusal":"I can't "}}]}),
            json!({"choices":[{"index":0_i32,"delta":{"refusal":"help with that."}}]}),
        ],
        false,
    );
    let whole = assemble(
        &[
            json!({"choices":[{"index":0_i32,"message":{"role":"assistant","content":null,"refusal":"I can't help with that."}}]}),
        ],
        false,
    );

    assert_eq!(
        role_texts(&streamed),
        [(EntryRole::Assistant, "I can't help with that.")]
    );
    assert_eq!(streamed.entries, whole.entries);
}

#[test]
fn messages_are_read_only_through_chat_fields() {
    // Responses item types mean nothing on a Chat Completions message.
    let conversation = ChatRequest::parse(
        Some(&json!({"messages":[
            {"type":"function_call","role":"user","content":"hello","call_id":"c1","arguments":"{}"}
        ]})),
        false,
    )
    .conversation();

    assert_eq!(
        summary(&conversation),
        [(EntryRole::User, "hello", None, None)]
    );
}
