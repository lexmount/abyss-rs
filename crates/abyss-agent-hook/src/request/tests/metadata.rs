//! String metadata keeps the same semantics in inspection and exchange observation.

use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, OriginalDestination, RequestTransport, RequestView,
    TransparentProtocol, WebSocketDirection, WebSocketMessage,
};
use http::{Request, Response};
use serde_json::{Value, json};

use crate::{HarnessUsageConfig, protocol, request::AgentRequestParser};

const CLAUDE_WEB_PATH: &str = "/api/organizations/org/chat_conversations/conversation-1/completion";

#[derive(Debug, PartialEq)]
struct Metadata {
    model: Option<String>,
    previous_response_id: Option<String>,
}

#[test]
fn http_request_metadata_normalizes_model_strings() {
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (path, base) in [
        ("/v1/responses", json!({"input":"hello"})),
        (
            "/v1/chat/completions",
            json!({"messages":[{"role":"user","content":"hello"}]}),
        ),
        (
            "/v1/messages",
            json!({"messages":[{"role":"user","content":"hello"}]}),
        ),
        (CLAUDE_WEB_PATH, json!({"prompt":"hello"})),
    ] {
        for (model, normalized) in [
            (json!("requested"), Some("requested")),
            (json!(" \trequested\n"), Some("requested")),
            (json!(""), None),
            (json!(" \t\n"), None),
            (Value::Null, None),
            (json!(42_i32), None),
        ] {
            let mut payload = base.clone();
            payload["model"] = model;
            for metadata in parse_metadata(path, &payload, RequestTransport::Http) {
                actual.push((path, metadata));
                expected.push((
                    path,
                    Metadata {
                        model: normalized.map(str::to_owned),
                        previous_response_id: None,
                    },
                ));
            }
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn http_request_metadata_normalizes_continuation_strings() {
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (kind, previous, normalized) in [
        (json!("continue"), json!("prior"), Some("prior")),
        (json!(" \tcontinue\n"), json!("prior"), Some("prior")),
        (json!("continue"), json!(" \tprior\n"), Some("prior")),
        (json!("continue"), json!(""), None),
        (json!("continue"), json!(" \t\n"), None),
        (json!("continue"), Value::Null, None),
        (json!("continue"), json!(42_i32), None),
        (json!("new"), json!("prior"), None),
        (json!(" \t\n"), json!("prior"), None),
        (Value::Null, json!("prior"), None),
    ] {
        let payload = json!({
            "messages":[{"role":"user","content":"hello"}],
            "thread":{"type":kind,"previous_message_id":previous},
            "previous_response_id":"must-not-override-thread"
        });
        for metadata in parse_metadata("/v1/messages", &payload, RequestTransport::Http) {
            actual.push(metadata);
            expected.push(Metadata {
                model: None,
                previous_response_id: normalized.map(str::to_owned),
            });
        }
    }
    assert_eq!(actual, expected);
}

#[test]
fn openai_request_metadata_normalizes_continuation_strings_for_http_and_websocket() {
    let mut actual = Vec::new();
    let mut expected = Vec::new();
    for (path, transport, base) in [
        (
            "/v1/responses",
            RequestTransport::Http,
            json!({"input":"hello"}),
        ),
        (
            "/v1/chat/completions",
            RequestTransport::Http,
            json!({"messages":[{"role":"user","content":"hello"}]}),
        ),
        (
            "/v1/responses",
            RequestTransport::WebSocketText { sequence: 1 },
            json!({"input":"hello"}),
        ),
    ] {
        for (previous, normalized) in [
            (json!("prior"), Some("prior")),
            (json!(" \tprior\n"), Some("prior")),
            (json!(""), None),
            (json!(" \t\n"), None),
            (Value::Null, None),
            (json!(42_i32), None),
        ] {
            let mut payload = base.clone();
            payload["previous_response_id"] = previous;
            for metadata in parse_metadata(path, &payload, transport) {
                actual.push(metadata);
                expected.push(Metadata {
                    model: None,
                    previous_response_id: normalized.map(str::to_owned),
                });
            }
        }
    }
    assert_eq!(actual, expected);
}

fn parse_metadata(path: &str, payload: &Value, transport: RequestTransport) -> [Metadata; 2] {
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
    let payload = if matches!(transport, RequestTransport::Http) {
        payload.clone()
    } else {
        json!({"type":"response.create","response":payload})
    };
    let body = CapturedBody::from_bytes(serde_json::to_vec(&payload).unwrap().into());
    let inspected = AgentRequestParser::parse(
        &RequestView {
            flow: &flow,
            head: &head,
            body: &body,
            transport,
        },
        &HarnessUsageConfig::default(),
        "request".to_owned(),
    )
    .agent
    .unwrap();
    let observed = if matches!(transport, RequestTransport::WebSocketText { .. }) {
        let message = WebSocketMessage::new(
            flow,
            head,
            Response::builder().status(101).body(()).unwrap(),
            WebSocketDirection::ClientToServer,
            1,
            Some(payload.to_string()),
            None,
        );
        let protocol::openai::responses::websocket::OpenAiWebSocketFrame::Request(parsed) =
            protocol::openai::parse_openai_websocket_message(&message)
        else {
            panic!("expected a request frame");
        };
        Metadata {
            model: parsed.model,
            previous_response_id: parsed.previous_response_id,
        }
    } else {
        let exchange = HttpExchange::new(
            flow,
            head.map(|()| body),
            Response::new(CapturedBody::from_bytes(b"{}".to_vec().into())),
        );
        match path {
            "/v1/messages" => {
                let parsed =
                    protocol::anthropic::parse_anthropic_messages_exchange(&exchange).unwrap();
                Metadata {
                    model: parsed.model,
                    previous_response_id: parsed.previous_response_id,
                }
            }
            CLAUDE_WEB_PATH => {
                let parsed = protocol::anthropic::parse_claude_web_exchange(&exchange).unwrap();
                Metadata {
                    model: parsed.model,
                    previous_response_id: None,
                }
            }
            _ => {
                let parsed = if path == "/v1/responses" {
                    protocol::openai::responses::parse_responses_exchange(&exchange)
                } else {
                    protocol::openai::chat_completions::parse_chat_completions_exchange(&exchange)
                }
                .unwrap();
                Metadata {
                    model: parsed.model,
                    previous_response_id: parsed.previous_response_id,
                }
            }
        }
    };
    [
        Metadata {
            model: inspected.model,
            previous_response_id: inspected.previous_response_id,
        },
        observed,
    ]
}
