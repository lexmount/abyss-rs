//! Ordinary `WorkBuddy` conversations exercised through the public hook boundary.
//! Synthetic exchanges verify correlation without credentials or live services.

use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, SourceProcess,
    TransparentProtocol,
};
use abyss_plugin_protocol::event::AgentEvent;
use http::{Request, Response};
use parking_lot::Mutex;
use serde_json::{Value, json};

#[derive(Debug, Default)]
struct RecordingSink {
    events: Mutex<Vec<AgentEvent>>,
}

impl AgentEventSink for RecordingSink {
    type Error = Infallible;

    fn publish(&self, event: AgentEvent) -> impl Future<Output = Result<(), Self::Error>> + Send {
        self.events.lock().push(event);
        std::future::ready(Ok(()))
    }
}

struct WorkBuddyScenario {
    sink: Arc<RecordingSink>,
    hook: HarnessUsageHook<Arc<RecordingSink>>,
}

impl WorkBuddyScenario {
    fn new(enabled: bool, conversation_text: bool) -> Self {
        let policy: HooksConfig = serde_json::from_value(json!({
            "harness_usage": {"enabled": true, "config": {"harnesses": {
                "workbuddy": {
                    "enabled": enabled,
                    "content": {"conversation_text": conversation_text}
                }
            }}}
        }))
        .unwrap();
        let sink = Arc::new(RecordingSink::default());
        let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::new(policy),
            Arc::clone(&sink),
        );
        Self { sink, hook }
    }

    async fn exchange(
        &self,
        process: &str,
        headers: &[(&str, &str)],
        messages: Value,
        reply_id: &str,
    ) {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(SourceProcess::new(None, Some(process.to_owned()), None)),
        );
        let mut request = Request::builder()
            .method("POST")
            .uri("/v2/chat/completions")
            .header("host", "www.workbuddy.cn")
            .header("user-agent", "axios/1.18.1");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let exchange = HttpExchange::new(
            flow,
            request.body(CapturedBody::from_bytes(json!({
                "model": "fixture-model", "messages": messages
            }).to_string().into_bytes().into())).unwrap(),
            Response::builder().header("content-type", "application/json")
                .body(CapturedBody::from_bytes(json!({
                    "id": reply_id,
                    "model": "fixture-model",
                    "choices": [{"index": 0_u32, "message": {"role": "assistant", "content": "Done."}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 10_u64, "completion_tokens": 5_u64, "total_tokens": 15_u64}
                }).to_string().into_bytes().into())).unwrap(),
        );
        self.hook.on_http_exchange(&exchange).await.unwrap();
    }
}

#[tokio::test]
async fn multi_turn_and_tool_continuation_preserve_session_and_turn_on_both_sides() {
    for conversation_text in [true, false] {
        let scenario = WorkBuddyScenario::new(true, conversation_text);
        let initial = json!([{"role": "user", "content": "Read the file."}]);
        let tool_followup = json!([
            {"role": "user", "content": "Read the file."},
            {"role": "assistant", "tool_calls": [{"id": "call-1", "type": "function", "function": {"name": "read_file", "arguments": "{}"}}]},
            {"role": "tool", "tool_call_id": "call-1", "content": "File contents."}
        ]);
        for (session, turn, message, messages) in [
            ("session-a", "turn-1", "message-1", initial.clone()),
            ("session-a", "turn-1", "message-2", tool_followup.clone()),
            // A repeated model attempt retains the declared user turn.
            ("session-a", "turn-1", "message-2", tool_followup),
            (
                "session-a",
                "turn-2",
                "message-3",
                json!([{"role": "user", "content": "Now summarize."}]),
            ),
            ("session-b", "turn-1", "message-4", initial),
        ] {
            scenario
                .exchange(
                    "WorkBuddy",
                    &[
                        ("X-Conversation-ID", session),
                        ("X-Conversation-Request-ID", turn),
                        ("X-Conversation-Message-ID", message),
                        ("X-Request-ID", message),
                    ],
                    messages,
                    message,
                )
                .await;
            let events = std::mem::take(&mut *scenario.sink.events.lock());
            assert_eq!(events.len(), 2);
            for event in events {
                assert_eq!(event.agent.name, "workbuddy");
                assert_eq!(event.session_id, session);
                assert_eq!(event.turn_id.as_deref(), Some(turn));
                assert_eq!(event.response_id.as_deref(), Some(message));
                assert_eq!(event.text.is_some(), conversation_text);
            }
        }
    }
}

#[tokio::test]
async fn existing_session_header_keeps_precedence_in_public_events() {
    let scenario = WorkBuddyScenario::new(true, true);
    scenario
        .exchange(
            "WorkBuddy",
            &[
                ("session-id", "existing-session"),
                ("X-Conversation-ID", "conversation-1"),
                ("X-Conversation-Request-ID", "turn-1"),
            ],
            json!([{"role": "user", "content": "Hello"}]),
            "reply-1",
        )
        .await;
    let events = scenario.sink.events.lock();
    assert_eq!(events.len(), 2);
    for event in events.iter() {
        assert_eq!(event.session_id, "existing-session");
        assert_eq!(event.turn_id.as_deref(), Some("turn-1"));
    }
}

#[tokio::test]
async fn absent_or_blank_headers_keep_existing_fallback_and_no_turn() {
    let scenario = WorkBuddyScenario::new(true, true);
    for headers in [
        vec![],
        vec![
            ("X-Conversation-ID", " "),
            ("X-Conversation-Request-ID", "\t"),
        ],
    ] {
        scenario
            .exchange(
                "WorkBuddy",
                &headers,
                json!([{"role": "user", "content": "Hello"}]),
                "reply-1",
            )
            .await;
        let events = std::mem::take(&mut *scenario.sink.events.lock());
        assert_eq!(events.len(), 2);
        for event in events {
            assert!(event.session_id.starts_with("flow-"));
            assert!(event.turn_id.is_none());
        }
    }
}

#[tokio::test]
async fn headers_alone_do_not_bypass_identity_or_disabled_policy() {
    for (enabled, process) in [(true, "node"), (false, "WorkBuddy")] {
        let scenario = WorkBuddyScenario::new(enabled, true);
        scenario
            .exchange(
                process,
                &[
                    ("X-Conversation-ID", "session-a"),
                    ("X-Conversation-Request-ID", "turn-1"),
                ],
                json!([{"role": "user", "content": "Hello"}]),
                "reply-1",
            )
            .await;
        assert!(scenario.sink.events.lock().is_empty());
    }
}
