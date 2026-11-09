//! Inspection projections preserve request content independently of audit settings.

mod metadata;
mod reuse;

use abyss_mitm::{
    CapturedBody, FlowContext, OriginalDestination, RequestView, TransparentProtocol,
};
use abyss_plugin_protocol::inspection::RequestParsingStatus;
use http::Request;

use super::AgentRequestParser;

#[test]
fn inspection_reuses_conversation_tools_and_harness_recognition_without_audit() {
    let flow = FlowContext::from_optional_addrs(
        None,
        None,
        OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
        TransparentProtocol::PlainHttp,
        None,
    );
    let head = Request::builder()
        .method("POST")
        .uri("/v1/responses")
        .header("host", "api.openai.com")
        .header("originator", "codex_cli_rs")
        .header("authorization", "Bearer secret")
        .header("cookie", "private")
        .header("x-api-key", "provider credential")
        .header("anthropic-api-key", "another credential")
        .header("chatgpt-account-id", "account credential")
        .body(())
        .unwrap();
    let payload = serde_json::json!({"model":"test-model","instructions":"system secret","input":[{"role":"user","content":"user secret"},{"type":"function_call_output","call_id":"call-1","output":"tool secret"}],"tools":[{"type":"function","name":"read","parameters":{"type":"object"}}],"extra":"unrecognized secret"});
    let body = CapturedBody::from_bytes(serde_json::to_vec(&payload).unwrap().into());
    let config: crate::HarnessUsageConfig = serde_json::from_value(serde_json::json!({"harnesses":{"codex":{"enabled":false}}, "content":{"conversation_text":false,"tool_calls":false,"images":false}})).unwrap();
    let result = AgentRequestParser::parse(
        &RequestView {
            flow: &flow,
            head: &head,
            body: &body,
            transport: abyss_mitm::RequestTransport::Http,
        },
        &config,
        "request-1".to_owned(),
    );
    assert!(
        matches!(result.parsing_status, RequestParsingStatus::Parsed),
        "known complete request must be projected"
    );
    assert!(
        result.source_process.is_none(),
        "explicit-style missing process must remain absent"
    );
    assert!(
        result.headers.iter().all(|(name, _)| !matches!(
            name.as_str(),
            "authorization" | "cookie" | "x-api-key" | "anthropic-api-key" | "chatgpt-account-id"
        )),
        "credentials must not reach the plugin"
    );
    assert_eq!(result.harness.unwrap().id, "codex");
    let agent = result.agent.unwrap();
    assert!(
        agent
            .conversation
            .entries
            .iter()
            .any(|entry| entry.role == abyss_plugin_protocol::event::EntryRole::Developer),
        "instructions share the observation projection"
    );
    assert!(agent.conversation.entries.iter().any(|entry| entry.role
        == abyss_plugin_protocol::event::EntryRole::ToolResult
        && entry.text == "tool secret"));
    assert_eq!(agent.tools.unwrap()[0]["name"], "read");
    assert_eq!(
        result.json.unwrap(),
        payload,
        "projection must not discard unknown raw fields"
    );
}

#[test]
fn unknown_and_invalid_requests_keep_full_content() {
    let flow = FlowContext::from_optional_addrs(
        None,
        None,
        OriginalDestination::from("127.0.0.1:80".parse::<std::net::SocketAddr>().unwrap()),
        TransparentProtocol::PlainHttp,
        None,
    );
    for (path, known) in [("/unknown", false), ("/v1/messages", true)] {
        let head = Request::builder().uri(path).body(()).unwrap();
        let body = CapturedBody::from_bytes(b"private plaintext".to_vec().into());
        let result = AgentRequestParser::parse(
            &RequestView {
                flow: &flow,
                head: &head,
                body: &body,
                transport: abyss_mitm::RequestTransport::Http,
            },
            &crate::HarnessUsageConfig::default(),
            "request".to_owned(),
        );
        assert!(
            result.agent.is_none(),
            "unsupported projection must not invent an event"
        );
        assert_eq!(
            matches!(result.parsing_status, RequestParsingStatus::InvalidPayload),
            known
        );
        let abyss_plugin_protocol::inspection::DecodedContent::Utf8(text) = result.body else {
            panic!("text body");
        };
        assert_eq!(text, "private plaintext");
    }
}

#[test]
fn request_and_observation_share_each_http_dialect_projection() {
    use crate::protocol::{anthropic, openai};
    use serde_json::json;

    for (path, payload) in [
        (
            "/v1/responses",
            json!({"model":"requested", "instructions":"system", "input":"hello"}),
        ),
        (
            "/v1/chat/completions",
            json!({"model":"requested", "messages":[{"role":"user","content":"hello"}]}),
        ),
        (
            "/v1/messages",
            json!({"model":"requested", "system":"system", "messages":[{"role":"user","content":"hello"}], "thread":{"type":"continue","previous_message_id":"prior"}}),
        ),
        (
            "/api/organizations/org/chat_conversations/conversation-1/completion",
            json!({"model":"requested", "prompt":"hello"}),
        ),
    ] {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
            TransparentProtocol::PlainHttp,
            None,
        );
        let head = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "gateway.example")
            .body(())
            .unwrap();
        let body = CapturedBody::from_bytes(serde_json::to_vec(&payload).unwrap().into());
        let inspected = AgentRequestParser::parse(
            &RequestView {
                flow: &flow,
                head: &head,
                body: &body,
                transport: abyss_mitm::RequestTransport::Http,
            },
            &crate::HarnessUsageConfig::default(),
            "request".to_owned(),
        )
        .agent
        .unwrap();
        let exchange = abyss_mitm::HttpExchange::new(
            flow,
            head.map(|()| body),
            http::Response::new(CapturedBody::from_bytes(b"{}".to_vec().into())),
        );
        let (conversation, model) = match path {
            "/v1/responses" => {
                let parsed = openai::responses::parse_responses_exchange(&exchange).unwrap();
                (parsed.request_conversation, parsed.model)
            }
            "/v1/chat/completions" => {
                let parsed =
                    openai::chat_completions::parse_chat_completions_exchange(&exchange).unwrap();
                (parsed.request_conversation, parsed.model)
            }
            "/v1/messages" => {
                let parsed = anthropic::parse_anthropic_messages_exchange(&exchange).unwrap();
                assert_eq!(inspected.previous_response_id, parsed.previous_response_id);
                (parsed.request_conversation, parsed.model)
            }
            _ => {
                let parsed = anthropic::parse_claude_web_exchange(&exchange).unwrap();
                (parsed.request_conversation, parsed.model)
            }
        };
        assert_eq!(
            serde_json::to_value(inspected.conversation).unwrap(),
            serde_json::to_value(conversation).unwrap(),
            "{path}"
        );
        assert_eq!(inspected.model, model, "{path}");
        assert_eq!(model.as_deref(), Some("requested"));
    }
}

#[test]
fn websocket_prewarm_uses_the_shared_request_projection_and_preserves_message_identity() {
    let flow = FlowContext::from_optional_addrs(
        None,
        None,
        OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
        TransparentProtocol::PlainHttp,
        None,
    );
    let head = Request::builder()
        .uri("/v1/responses")
        .header("host", "api.openai.com")
        .header("originator", "codex_cli_rs")
        .header("thread-id", "child")
        .header("x-codex-parent-thread-id", "parent")
        .header("session-id", "main")
        .header(
            "x-codex-turn-metadata",
            r#"{"root_turn_id":"stale-upgrade-turn"}"#,
        )
        .body(())
        .unwrap();
    let bytes = br#"{"type":"response.create","response":{"generate":false,"model":"requested","input":"sensitive prewarm","previous_response_id":"prior","client_metadata":{"x-codex-turn-metadata":"{\"root_turn_id\":\"current-turn\"}"}}}"#;
    let body = CapturedBody::from_bytes(bytes.to_vec().into());
    let inspected = AgentRequestParser::parse(
        &RequestView {
            flow: &flow,
            head: &head,
            body: &body,
            transport: abyss_mitm::RequestTransport::WebSocketBinary { sequence: 2 },
        },
        &crate::HarnessUsageConfig::default(),
        "request".to_owned(),
    );
    assert_eq!(inspected.sequence, 2);
    let harness = inspected.harness.as_ref().unwrap();
    assert_eq!(harness.subagent_id.as_deref(), Some("child"));
    assert_eq!(harness.parent_subagent_id.as_deref(), Some("parent"));
    assert_eq!(harness.turn_id.as_deref(), Some("current-turn"));
    assert!(matches!(
        inspected.message_type,
        Some(abyss_plugin_protocol::inspection::RequestMessageType::Binary)
    ));
    let observed = crate::protocol::openai::parse_openai_websocket_message(
        &abyss_mitm::WebSocketMessage::new(
            flow,
            head,
            http::Response::builder().status(101).body(()).unwrap(),
            abyss_mitm::WebSocketDirection::ClientToServer,
            2,
            None,
            Some(bytes.to_vec().into()),
        ),
    );
    let crate::protocol::openai::responses::websocket::OpenAiWebSocketFrame::Request(observed) =
        observed
    else {
        panic!("prewarm request must be parsed");
    };
    let inspected = inspected.agent.unwrap();
    assert_eq!(
        serde_json::to_value(inspected.conversation).unwrap(),
        serde_json::to_value(observed.request_conversation).unwrap()
    );
    assert_eq!(inspected.model, observed.model);
    assert_eq!(
        inspected.previous_response_id,
        observed.previous_response_id
    );
    assert_eq!(observed.generates_output, Some(false));
}
