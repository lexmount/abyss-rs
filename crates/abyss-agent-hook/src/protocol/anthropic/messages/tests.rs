//! Messages exchange regression cases.

use std::net::SocketAddr;

use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
};
use abyss_plugin_protocol::event::EntryRole;
use http::{Request, Response};
use serde_json::{Value, json};

use super::parse_anthropic_messages_exchange;
use crate::protocol::model::conversation::role_texts;

#[test]
fn parses_messages_json_without_harness_assumptions() {
    let exchange = json_exchange(
        "/v1/messages",
        &json!({
            "model": "claude-test",
            "messages": [{"role": "user", "content": "hello"}]
        }),
        &json!({
            "id": "msg_1",
            "model": "claude-test",
            "content": [{"type": "text", "text": "hi"}],
            "usage": {"input_tokens": 3_i32, "output_tokens": 4_i32}
        }),
    );

    let parsed = parse_anthropic_messages_exchange(&exchange).expect("Anthropic Messages exchange");

    assert_eq!(parsed.session_id, "session-1");
    assert_eq!(
        role_texts(&parsed.request_conversation),
        [(EntryRole::User, "hello")]
    );
    assert_eq!(
        role_texts(&parsed.response_conversation),
        [(EntryRole::Assistant, "hi")]
    );
    assert_eq!(parsed.message_id.as_deref(), Some("msg_1"));
    assert_eq!(parsed.model.as_deref(), Some("claude-test"));
    assert_eq!(parsed.usage.input_tokens, 3);
    assert_eq!(parsed.usage.output_tokens, 4);
}

#[test]
fn parses_messages_sse_usage_and_tool_call() {
    let request = json!({
        "model": "claude-test",
        "messages": [{"role": "user", "content": "run pwd"}]
    });
    let response = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",",
        "\"model\":\"claude-test\",\"usage\":{\"input_tokens\":5}}}\n\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
        "{\"type\":\"tool_use\",\"id\":\"tool-1\",\"name\":\"Bash\",\"input\":{}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":",
        "{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"pwd\\\"}\"}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\n\n"
    );
    let exchange = sse_exchange("/v1/messages", &request, response.as_bytes());

    let parsed = parse_anthropic_messages_exchange(&exchange).expect("Anthropic SSE exchange");

    assert_eq!(parsed.message_id.as_deref(), Some("msg_2"));
    assert_eq!(
        role_texts(&parsed.response_conversation),
        [(EntryRole::ToolCall, "{\"command\":\"pwd\"}")]
    );
    assert_eq!(parsed.usage.input_tokens, 5);
    assert_eq!(parsed.usage.output_tokens, 2);
}

#[test]
fn keeps_messages_cache_counters_disjoint_from_input() {
    let request = json!({
        "model": "claude-test",
        "messages": [{"role": "user", "content": "continue"}]
    });
    let response = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_3\",",
        "\"model\":\"claude-test\",\"usage\":{\"input_tokens\":2,",
        "\"cache_read_input_tokens\":77000,\"cache_creation_input_tokens\":400,",
        "\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":2,",
        "\"cache_read_input_tokens\":77000,\"cache_creation_input_tokens\":400,",
        "\"output_tokens\":150}}\n\n"
    );
    let exchange = sse_exchange("/v1/messages", &request, response.as_bytes());

    let parsed = parse_anthropic_messages_exchange(&exchange).expect("Anthropic SSE exchange");

    assert_eq!(parsed.usage.input_tokens, 2);
    assert_eq!(parsed.usage.cache_read_tokens, 77_000);
    assert_eq!(parsed.usage.cache_write_tokens, 400);
    assert_eq!(parsed.usage.output_tokens, 150);
    assert_eq!(parsed.usage.total_tokens, 77_552);
}

#[test]
fn parses_tool_result_from_latest_user_message() {
    let exchange = json_exchange(
        "/v1/messages",
        &json!({
            "model": "claude-test",
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "tool-1", "name": "Read", "input": {"path": "a"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tool-1", "content": "file contents"}
                ]}
            ]
        }),
        &json!({
            "id": "msg-3",
            "content": [{"type": "text", "text": "done"}],
            "usage": {"input_tokens": 8_i32, "output_tokens": 1_i32}
        }),
    );

    let parsed = parse_anthropic_messages_exchange(&exchange).expect("tool-result exchange");

    assert_eq!(
        role_texts(&parsed.request_conversation),
        [
            (EntryRole::ToolCall, "{\"path\":\"a\"}"),
            (EntryRole::ToolResult, "file contents"),
        ]
    );
}

#[test]
fn correlates_messages_with_native_deepseek_session_header() {
    for (session_id, text) in [
        ("session-web-1", "read observation-demo.txt"),
        ("session-web-1", "summarize the previous tool result"),
        ("session-web-2", "read observation-demo.txt"),
    ] {
        let mut exchange = json_exchange(
            "/anthropic/v1/messages",
            &json!({
                "model": "deepseek-flash",
                "messages": [{"role": "user", "content": text}]
            }),
            &json!({"content": [{"type": "text", "text": "done"}]}),
        );
        exchange.request.headers_mut().remove("session-id");
        exchange.request.headers_mut().insert(
            "x-deepseek-harness-session-id",
            format!(" {session_id} ").parse().unwrap(),
        );

        let parsed = parse_anthropic_messages_exchange(&exchange).expect("Messages exchange");

        assert_eq!(parsed.session_id, session_id);
        assert_eq!(
            role_texts(&parsed.request_conversation),
            [(EntryRole::User, text)]
        );
    }
}

#[test]
fn ignores_blank_deepseek_session_header() {
    let mut exchange = json_exchange(
        "/anthropic/v1/messages",
        &json!({"messages": [{"role": "user", "content": "hello"}]}),
        &json!({"content": [{"type": "text", "text": "hi"}]}),
    );
    exchange
        .request
        .headers_mut()
        .insert("x-deepseek-harness-session-id", "  ".parse().unwrap());

    let parsed = parse_anthropic_messages_exchange(&exchange).expect("fallback header");
    assert_eq!(parsed.session_id, "session-1");

    exchange.request.headers_mut().remove("session-id");
    let parsed = parse_anthropic_messages_exchange(&exchange).expect("unattributed exchange");
    assert_eq!(parsed.session_id, "anthropic-unattributed-gateway-example");
}

#[test]
fn hermes_session_headers_follow_messages_precedence_and_fallbacks() {
    for name in ["x-hermes-session-id", "session_id"] {
        let mut exchange = json_exchange(
            "/v1/messages",
            &json!({"messages": [{"role": "user", "content": "hello"}]}),
            &json!({"content": [{"type": "text", "text": "hi"}]}),
        );
        let headers = exchange.request.headers_mut();
        headers.remove("session-id");
        headers.insert(name, " hermes-session ".parse().unwrap());
        headers.insert(
            "x-claude-code-session-id",
            "claude-session".parse().unwrap(),
        );
        let parsed = parse_anthropic_messages_exchange(&exchange).unwrap();
        assert_eq!(parsed.session_id, "claude-session");

        exchange
            .request
            .headers_mut()
            .remove("x-claude-code-session-id");
        let parsed = parse_anthropic_messages_exchange(&exchange).unwrap();
        assert_eq!(parsed.session_id, "hermes-session");

        exchange
            .request
            .headers_mut()
            .insert(name, " ".parse().unwrap());
        let parsed = parse_anthropic_messages_exchange(&exchange).unwrap();
        assert_eq!(parsed.session_id, "anthropic-unattributed-gateway-example");
    }
}

#[test]
fn retains_unattributed_session_bucket_when_protocol_has_no_session_id() {
    let mut exchange = json_exchange(
        "/v1/messages",
        &json!({
            "model": "claude-test",
            "messages": [{"role": "user", "content": "hello"}]
        }),
        &json!({
            "content": [{"type": "text", "text": "hi"}],
            "usage": {"input_tokens": 1_i32, "output_tokens": 1_i32}
        }),
    );
    exchange.request.headers_mut().remove("session-id");

    let parsed = parse_anthropic_messages_exchange(&exchange).expect("unattributed exchange");

    assert_eq!(parsed.session_id, "anthropic-unattributed-gateway-example");
}

const CLAUDE_CODE_TURN_13: &str = "x-anthropic-billing-header: cc_version=2.1.100.abc; cc_entrypoint=cli; cch=00001; cc_prev_req=req_011CSyntheticRequest0001; cc_prompt_id=00000000-0000-4000-8000-000000000001; cc_turn_origin=human; cc_prompt_index=13; cc_turn_index=13;";

/// Claude Code request bodies of one user turn (`cc_turn_index=13`), with
/// synthetic identities: a `continue` that failed with `thread_not_found`,
/// its `create` replay under a new `cc_prompt_id`, and a later
/// tool-result-only `continue`.
fn claude_code_turn_13_requests() -> [Value; 3] {
    [
        json!({
            "model": "claude-opus-5-5",
            "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.100.abc; cc_entrypoint=cli; cch=00002; cc_prev_req=req_011CSyntheticRequest0002; cc_prompt_id=00000000-0000-4000-8000-000000000002; cc_turn_origin=human; cc_prompt_index=13; cc_turn_index=13;"}],
            "messages": [
                {"role": "user", "content": "look at the thread field"},
                {"role": "system", "content": [{"type": "text", "text": "<reminder>synthetic system note</reminder>"}]}
            ],
            "thread": {"type": "continue", "previous_message_id": "msg_011CSyntheticMessage0001"},
            "stream": true
        }),
        json!({
            "model": "claude-opus-5-5",
            "system": [
                {"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.100.abc; cc_entrypoint=cli; cch=00003; cc_prev_req=req_011CSyntheticRequest0002; cc_prompt_id=00000000-0000-4000-8000-000000000001; cc_turn_origin=human; cc_prompt_index=13; cc_turn_index=13;"},
                {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
            ],
            "messages": [
                {"role": "user", "content": "earlier prompt"},
                {"role": "assistant", "content": [{"type": "text", "text": "earlier answer"}]},
                {"role": "user", "content": "look at the thread field"},
                {"role": "system", "content": [{"type": "text", "text": "<reminder>synthetic system note</reminder>"}]}
            ],
            "tools": [{"name": "Bash", "input_schema": {"type": "object"}}],
            "thread": {"type": "create"},
            "stream": true
        }),
        json!({
            "model": "claude-opus-5-5",
            "system": [{"type": "text", "text": CLAUDE_CODE_TURN_13}],
            "messages": [
                {"role": "user", "content": [
                    {"tool_use_id": "toolu_01SyntheticToolUse000001", "type": "tool_result", "content": "ok"}
                ]},
                {"role": "system", "content": [{"type": "text", "text": "<reminder>synthetic system note</reminder>"}]}
            ],
            "thread": {"type": "continue", "previous_message_id": "msg_011CSyntheticMessage0002"},
            "stream": true
        }),
    ]
}

#[test]
fn only_a_thread_continue_names_the_response_it_continues_after() {
    let parsed = claude_code_turn_13_requests().map(|request| {
        parse_anthropic_messages_exchange(&json_exchange("/v1/messages", &request, &json!({})))
            .expect("Claude Code exchange")
    });

    assert_eq!(
        parsed
            .each_ref()
            .map(|exchange| exchange.previous_response_id.as_deref()),
        [
            Some("msg_011CSyntheticMessage0001"),
            None,
            Some("msg_011CSyntheticMessage0002"),
        ]
    );
}

#[test]
fn response_id_is_the_message_id_of_the_conversation() {
    let request = json!({"messages": [{"role": "user", "content": "hello"}]});
    // A stream names its message in `message_start.message.id`.
    let streamed = parse_anthropic_messages_exchange(&sse_exchange(
            "/v1/messages",
            &request,
            concat!(
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"content\":[]}}\n\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
                "data: {\"type\":\"message_stop\"}\n\n"
            )
            .as_bytes(),
        ))
        .expect("SSE exchange");
    assert_eq!(streamed.message_id.as_deref(), Some("m1"));
    assert_eq!(streamed.response_conversation.entries[0].text, "hi");

    // A whole message names itself in its top-level `id`; an id in the
    // request is never the response's.
    let whole = parse_anthropic_messages_exchange(&json_exchange(
        "/v1/messages",
        &json!({"id": "msg_request", "messages": [{"role": "user", "content": "hello"}]}),
        &json!({"id": "m2", "type": "message", "content": [{"type": "text", "text": "hi"}]}),
    ))
    .expect("JSON exchange");
    assert_eq!(whole.message_id.as_deref(), Some("m2"));
    assert_eq!(whole.response_conversation.entries[0].text, "hi");
}

#[test]
fn rejects_non_dialogue_payload() {
    let exchange = json_exchange(
        "/v1/messages",
        &json!({"model": "claude-test", "metadata": {"operation": "bootstrap"}}),
        &json!({}),
    );

    assert!(parse_anthropic_messages_exchange(&exchange).is_none());
}

fn json_exchange(path: &str, request: &Value, response: &Value) -> HttpExchange {
    exchange(
        path,
        request,
        "application/json",
        serde_json::to_vec(response).unwrap(),
    )
}

fn sse_exchange(path: &str, request: &Value, response: &[u8]) -> HttpExchange {
    exchange(path, request, "text/event-stream", response.to_vec())
}

fn exchange(
    path: &str,
    request_body: &Value,
    response_content_type: &str,
    response_body: Vec<u8>,
) -> HttpExchange {
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("host", "gateway.example")
        .header("session-id", "session-1")
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .body(CapturedBody::from_bytes(
            serde_json::to_vec(request_body).unwrap().into(),
        ))
        .unwrap();
    let response = Response::builder()
        .header("content-type", response_content_type)
        .body(CapturedBody::from_bytes(response_body.into()))
        .unwrap();
    HttpExchange::new(flow(), request, response)
}

fn flow() -> FlowContext {
    FlowContext::new(
        SocketAddr::from(([127, 0, 0, 1], 50000)),
        SocketAddr::from(([127, 0, 0, 1], 18090)),
        OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
        TransparentProtocol::TlsHttp {
            server_name: "gateway.example".to_owned(),
        },
    )
}

#[test]
fn conversation_header_uses_the_existing_messages_session_chain() {
    let mut exchange = json_exchange(
        "/v1/messages",
        &json!({"messages": [{"role": "user", "content": "hello"}]}),
        &json!({"content": [{"type": "text", "text": "hi"}]}),
    );
    exchange.request.headers_mut().insert(
        http::HeaderName::from_bytes(b"X-Conversation-ID").unwrap(),
        " conversation-1 ".parse().unwrap(),
    );
    assert_eq!(
        parse_anthropic_messages_exchange(&exchange)
            .unwrap()
            .session_id,
        "session-1"
    );
    exchange.request.headers_mut().remove("session-id");
    let parsed = parse_anthropic_messages_exchange(&exchange).unwrap();
    assert_eq!(parsed.session_id, "conversation-1");
    exchange
        .request
        .headers_mut()
        .insert("x-conversation-id", " \t".parse().unwrap());
    let parsed = parse_anthropic_messages_exchange(&exchange).unwrap();
    assert_eq!(parsed.session_id, "anthropic-unattributed-gateway-example");
}
