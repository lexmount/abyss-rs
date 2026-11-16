//! Public HTTP and WebSocket capture-to-event completeness contracts.

use std::{convert::Infallible, fmt::Write as _, future::Future, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, SourceProcess,
    TransparentProtocol, WebSocketDirection, WebSocketMessage,
};
use abyss_plugin_protocol::event::AgentEvent;
use http::{Request, Response, Version};
use parking_lot::Mutex;
use serde_json::{Value, json};

#[derive(Debug, Default)]
struct Events(Mutex<Vec<AgentEvent>>);

impl AgentEventSink for Events {
    type Error = Infallible;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.0.lock().push(event);
        std::future::ready(Ok(()))
    }
}

struct Harness {
    sink: Arc<Events>,
    hook: HarnessUsageHook<Arc<Events>>,
    flow: FlowContext,
}

impl Harness {
    fn new() -> Self {
        let sink = Arc::new(Events::default());
        let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::new(HooksConfig::default()),
            sink.clone(),
        );
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
            TransparentProtocol::TlsHttp {
                server_name: "gateway.test".to_owned(),
            },
            Some(SourceProcess::new(Some(42), Some("codex".to_owned()), None)),
        );
        Self { sink, hook, flow }
    }

    fn request() -> Request<()> {
        Request::builder()
            .method("POST")
            .uri("https://gateway.test/v1/responses")
            .header("host", "gateway.test")
            .header("content-type", "application/json")
            .header("session-id", "response-completeness-test")
            .body(())
            .unwrap()
    }

    fn terminal() -> Value {
        json!({"type":"response.completed","response":{
            "id":"resp_fixture","model":"fixture-model","status":"completed",
            "output":[{"id":"msg_fixture","type":"message","role":"assistant",
                "content":[{"type":"output_text","text":"answer"}]}],
            "usage":{"input_tokens":3_i32,"output_tokens":2_i32,"total_tokens":5_i32}
        }})
    }

    fn assert_response(&self, completeness: &str, has_usage: bool) {
        let events: Vec<Value> = self
            .sink
            .0
            .lock()
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect();
        assert_eq!(events.len(), 2, "one request and one response event");
        let response = events
            .iter()
            .find(|event| event["side"] == "response")
            .unwrap();
        assert_eq!(
            response["agent"]["name"], "codex",
            "source identity survives parsing"
        );
        assert_eq!(
            response["session_id"], "response-completeness-test",
            "client session survives parsing"
        );
        assert_eq!(
            response["conversation"]["entries"][0]["text"], "answer",
            "retained content survives parsing"
        );
        assert_eq!(
            response["conversation"]["completeness"], completeness,
            "completeness reflects observation gaps"
        );
        if has_usage {
            assert_eq!(
                response["token_usage"]["output_tokens"], 2_i32,
                "terminal usage survives parsing"
            );
        }
    }

    async fn http(&self, payload: String, truncated: bool) {
        let mut request = Self::request().map(|()| {
            CapturedBody::from_bytes(
                br#"{"model":"fixture-model","input":"hello"}"#.to_vec().into(),
            )
        });
        *request.version_mut() = Version::HTTP_2;
        let bytes = payload.into_bytes().into();
        let body = if truncated {
            CapturedBody::from_truncated_bytes(bytes)
        } else {
            CapturedBody::from_bytes(bytes)
        };
        let response = Response::builder()
            .version(Version::HTTP_2)
            .header("content-type", "text/event-stream")
            .body(body)
            .unwrap();
        let exchange = HttpExchange::new(self.flow.clone(), request, response);
        self.hook.on_http_exchange(&exchange).await.unwrap();
        assert_eq!(
            exchange.response.body().raw_truncated(),
            truncated,
            "raw capture remains unchanged"
        );
        assert_eq!(
            exchange.response.body().truncated(),
            truncated,
            "capture state remains unchanged"
        );
    }

    async fn websocket(&self, direction: WebSocketDirection, sequence: u64, payload: String) {
        self.hook
            .on_websocket_message(&WebSocketMessage::new(
                self.flow.clone(),
                Self::request(),
                Response::builder().status(101).body(()).unwrap(),
                direction,
                sequence,
                Some(payload),
                None,
            ))
            .await
            .unwrap();
    }

    async fn start_websocket(&self) {
        self.websocket(
            WebSocketDirection::ClientToServer,
            0,
            json!({"type":"response.create","response":{"model":"fixture-model","input":"hello"}})
                .to_string(),
        )
        .await;
    }
}

#[tokio::test]
async fn http_terminal_snapshot_recovers_only_capture_truncation() {
    for completed in [false, true] {
        for malformed in [false, true] {
            for truncated in [false, true] {
                let harness = Harness::new();
                let mut payload = "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"answer\"}\n\n".to_owned();
                if malformed {
                    payload.push_str("data: {broken\n\n");
                }
                if completed {
                    write!(payload, "data: {}\n\n", Harness::terminal()).unwrap();
                }
                harness.http(payload, truncated).await;
                harness.assert_response(
                    if malformed || (truncated && !completed) {
                        "partial"
                    } else {
                        "complete"
                    },
                    completed,
                );
            }
        }
    }
}

#[tokio::test]
async fn http_decode_failure_after_snapshot_remains_partial() {
    for truncated in [false, true] {
        let harness = Harness::new();
        harness
            .http(
                format!("data: {}\n\ndata: {{broken\n\n", Harness::terminal()),
                truncated,
            )
            .await;
        harness.assert_response("partial", true);
    }
}

#[tokio::test]
async fn websocket_terminal_snapshot_does_not_hide_decode_failure() {
    for malformed in [false, true] {
        let harness = Harness::new();
        harness.start_websocket().await;
        if malformed {
            harness
                .websocket(WebSocketDirection::ServerToClient, 1, "{broken".to_owned())
                .await;
        }
        harness
            .websocket(
                WebSocketDirection::ServerToClient,
                2,
                Harness::terminal().to_string(),
            )
            .await;
        harness.assert_response(if malformed { "partial" } else { "complete" }, true);
    }
}

#[tokio::test]
async fn websocket_terminal_snapshot_does_not_hide_exhausted_assembly_budget() {
    let harness = Harness::new();
    harness.start_websocket().await;
    let payload = json!({"type":"response.output_text.done","output_index":0_i32,"content_index":0_i32,"text":"answer"}).to_string();
    // Fill the public turn budget with valid content-bearing frames; the terminal
    // frame still publishes usage but cannot make the discarded snapshot complete.
    for sequence in 1..=4096 {
        harness
            .websocket(
                WebSocketDirection::ServerToClient,
                sequence,
                payload.clone(),
            )
            .await;
    }
    harness
        .websocket(
            WebSocketDirection::ServerToClient,
            4097,
            Harness::terminal().to_string(),
        )
        .await;
    harness.assert_response("partial", true);
}
