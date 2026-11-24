//! Synthetic byte stream coverage for Claude Code hook attribution and delivery.

use std::{convert::Infallible, future, net::SocketAddr, sync::Mutex, time::Duration};

use abyss_mitm::{CapturedBody, HttpExchange, MitmHook, OriginalDestination, TransparentProtocol};
use abyss_plugin_protocol::event::{AgentEvent, AgentEventSide, ContentCompleteness, EntryRole};
use http::header::CONTENT_TYPE;
use serde_json::{Value, json};

use super::*;
use crate::{DeviceIdentity, HooksConfig};

const PATH: &str = "/v1/code/sessions/cse_test/events/stream";

#[derive(Debug, Default)]
struct RecordingSink(Mutex<Vec<AgentEvent>>);

impl AgentEventSink for RecordingSink {
    type Error = Infallible;

    fn publish(
        &self,
        event: AgentEvent,
    ) -> impl future::Future<Output = Result<(), Self::Error>> + Send {
        self.0.lock().unwrap().push(event);
        future::ready(Ok(()))
    }
}

fn fixture() -> (
    HarnessUsageHook<Arc<RecordingSink>>,
    Arc<RecordingSink>,
    FlowContext,
) {
    let sink = Arc::new(RecordingSink::default());
    let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
        HarnessUsageHookConfig::new(DeviceIdentity::new()),
        HooksRuntimeConfig::default_enabled(),
        Arc::clone(&sink),
    );
    let flow = FlowContext::from_optional_addrs(
        None,
        None,
        OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
        TransparentProtocol::TlsHttp {
            server_name: "claude.ai".to_owned(),
        },
        None,
    );
    (hook, sink, flow)
}

fn request(path: &str) -> Request<()> {
    Request::builder()
        .uri(path)
        .header("anthropic-client-app", "com.anthropic.claudefordesktop")
        .body(())
        .unwrap()
}

fn response() -> Response<()> {
    Response::builder()
        .header(CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .body(())
        .unwrap()
}

fn sse(payload: &Value) -> String {
    format!("data: {}\r\n\r\n", json!({"payload":payload}))
}

fn message(id: &str, event: &Value) -> String {
    sse(&json!({"type":"stream_event","api_message_id":id,"event":event}))
}

fn start(id: &str) -> String {
    message(id, &start_event(id))
}

fn start_event(id: &str) -> Value {
    json!({"type":"message_start","message":{
        "id":id,"model":"claude-test","content":[],
        "usage":{"input_tokens":7_i32,"output_tokens":1_i32,"cache_read_input_tokens":10_i32,"cache_creation_input_tokens":11_i32}
    }})
}

fn stop(id: &str) -> String {
    message(id, &json!({"type":"message_stop"}))
}

#[tokio::test]
async fn emits_interleaved_calls_at_message_stop_and_replays_response_ids() {
    let (hook, sink, flow) = fixture();
    let response = response();
    for path in [PATH, "/v1/code/sessions/session_test/events/stream"] {
        let mut observer = hook
            .observe_http_response(&flow, &request(path), &response)
            .unwrap();
        let user = sse(&json!({"type":"user","message":{"role":"user","content":[
            {"type":"tool_result","tool_use_id":"tool_1","content":"observed content"}
        ]}}));
        let wire = [
            user,
            start("msg_left"),
            start("msg_right"),
            message(
                "msg_left",
                &json!({"type":"message_delta","usage":{
                    "output_tokens":23_i32,"iterations":[{"output_tokens":99_i32}]
                }}),
            ),
            stop("msg_right"),
            stop("msg_left"),
        ]
        .concat();
        for chunk in wire.as_bytes().chunks(7) {
            observer
                .on_http_response_chunk(SystemTime::UNIX_EPOCH, chunk)
                .await
                .unwrap();
        }
        assert!(!sink.0.lock().unwrap().is_empty());
    }
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 8);
    assert!(events.iter().all(|event| event.session_id == "session_test"
        && event.agent.name == "claude-desktop"
        && event.llm.model == "claude-test"));
    assert_eq!(events[0].side, AgentEventSide::Request);
    let request = events[0].conversation.as_ref().unwrap();
    assert_eq!(request.completeness, ContentCompleteness::Complete);
    assert_eq!(request.entries[0].role, EntryRole::ToolResult);
    assert_eq!(request.entries[0].call_id.as_deref(), Some("tool_1"));
    assert_eq!(events[1].response_id.as_deref(), Some("msg_right"));
    assert!(events[2].conversation.as_ref().unwrap().entries.is_empty());
    assert_eq!(events[2].token_usage.input_tokens, 7);
    assert_eq!(events[2].token_usage.cache_read_tokens, 10);
    assert_eq!(events[2].token_usage.cache_write_tokens, 11);
    assert_eq!(events[3].response_id.as_deref(), Some("msg_left"));
    assert_eq!(events[3].token_usage.output_tokens, 23);
    assert_eq!(events[1].event_id, events[5].event_id);
    assert_eq!(events[3].event_id, events[7].event_id);
}

#[tokio::test]
async fn subtracts_ttft_from_the_message_start_block_time() {
    let times = call_times(Some(250)).await;
    assert_eq!(
        times,
        [
            "1970-01-01T00:00:00.750Z".parse().unwrap(),
            jiff::Timestamp::from_second(2).unwrap()
        ]
    );
}

#[tokio::test]
async fn uses_the_message_stop_block_time_on_both_sides_without_ttft() {
    assert_eq!(
        call_times(None).await,
        [jiff::Timestamp::from_second(2).unwrap(); 2]
    );
}

async fn call_times(ttft_ms: Option<u64>) -> [jiff::Timestamp; 2] {
    let (hook, sink, flow) = fixture();
    let mut observer = hook
        .observe_http_response(&flow, &request(PATH), &response())
        .unwrap();
    let mut payload = json!({
        "type": "stream_event",
        "api_message_id": "msg_test",
        "event": start_event("msg_test"),
    });
    if let Some(ttft_ms) = ttft_ms {
        payload["ttft_ms"] = json!(ttft_ms);
    }
    observer
        .on_http_response_chunk(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(1))
                .unwrap(),
            sse(&payload).as_bytes(),
        )
        .await
        .unwrap();
    observer
        .on_http_response_chunk(
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(2))
                .unwrap(),
            stop("msg_test").as_bytes(),
        )
        .await
        .unwrap();
    let events = sink.0.lock().unwrap();
    assert_eq!(events.len(), 2);
    [events[0].observed_at, events[1].observed_at]
}

#[tokio::test]
async fn requires_harness_attribution_and_skips_the_completed_session_exchange() {
    let (hook, sink, flow) = fixture();
    let unattributed = Request::builder().uri(PATH).body(()).unwrap();
    assert!(
        hook.observe_http_response(&flow, &unattributed, &response())
            .is_none()
    );
    let exchange = HttpExchange::new(
        flow,
        request(PATH).map(|()| CapturedBody::from_bytes(Vec::new().into())),
        response().map(|()| CapturedBody::from_bytes(start("msg_test").into())),
    );
    hook.on_http_exchange(&exchange).await.unwrap();
    assert!(sink.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn policy_reset_discards_an_unfinished_call() {
    let (hook, sink, flow) = fixture();
    let mut observer = hook
        .observe_http_response(&flow, &request(PATH), &response())
        .unwrap();
    observer
        .on_http_response_chunk(SystemTime::UNIX_EPOCH, start("msg_dropped").as_bytes())
        .await
        .unwrap();
    let mut disabled = HooksConfig::default();
    disabled.harness_usage.enabled = false;
    drop(hook.runtime_config.update(disabled));
    observer
        .on_http_response_chunk(SystemTime::UNIX_EPOCH, stop("msg_dropped").as_bytes())
        .await
        .unwrap();
    drop(hook.runtime_config.update(HooksConfig::default()));
    observer
        .on_http_response_chunk(SystemTime::UNIX_EPOCH, stop("msg_dropped").as_bytes())
        .await
        .unwrap();
    assert!(sink.0.lock().unwrap().is_empty());
}
