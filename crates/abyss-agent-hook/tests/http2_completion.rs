//! Public capture-to-event boundary for HTTP/2 cancellation after application completion.

use std::{convert::Infallible, fmt::Write as _, future::Future, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, SourceProcess,
    TransparentProtocol,
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

#[tokio::test]
async fn terminal_snapshot_completes_events_without_clearing_transport_truncation() {
    for completed in [false, true] {
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
        let request = Request::builder()
            .method("POST")
            .version(Version::HTTP_2)
            .uri("https://gateway.test/v1/responses")
            .header("host", "gateway.test")
            .header("content-type", "application/json")
            .header("session-id", "http2-completion-test")
            .body(CapturedBody::from_bytes(
                br#"{"model":"fixture-model","input":"hello"}"#.to_vec().into(),
            ))
            .unwrap();
        let mut payload = "data: {\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"answer\"}\n\n".to_owned();
        if completed {
            let terminal = json!({"type":"response.completed","response":{
                "id":"resp_fixture","model":"fixture-model","status":"completed",
                "output":[{"id":"msg_fixture","type":"message","role":"assistant",
                    "content":[{"type":"output_text","text":"answer"}]}],
                "usage":{"input_tokens":3_i32,"output_tokens":2_i32,"total_tokens":5_i32}
            }});
            write!(payload, "data: {terminal}\n\n").unwrap();
        }
        let response = Response::builder()
            .version(Version::HTTP_2)
            .header("content-type", "text/event-stream")
            .body(CapturedBody::from_truncated_bytes(
                payload.into_bytes().into(),
            ))
            .unwrap();
        let exchange = HttpExchange::new(flow, request, response);
        hook.on_http_exchange(&exchange).await.unwrap();
        assert!(exchange.response.body().raw_truncated());
        assert!(exchange.response.body().truncated());
        let events: Vec<Value> = sink
            .0
            .lock()
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect();
        assert_eq!(events.len(), 2);
        let response = events
            .iter()
            .find(|event| event["side"] == "response")
            .unwrap();
        assert_eq!(response["agent"]["name"], "codex");
        assert_eq!(response["session_id"], "http2-completion-test");
        assert_eq!(response["conversation"]["entries"][0]["text"], "answer");
        assert_eq!(
            response["conversation"]["completeness"],
            if completed { "complete" } else { "partial" }
        );
        if completed {
            assert_eq!(response["token_usage"]["output_tokens"], 2_i32);
        }
    }
}
