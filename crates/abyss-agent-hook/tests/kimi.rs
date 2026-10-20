//! Kimi wire contracts exercised through the public Agent Hook boundary.
//! Fixtures are synthetic and credential-free; live DSH verification is separate.

use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, TransparentProtocol,
};
use abyss_plugin_protocol::event::{AgentEvent, ContentCompleteness, MessageRole};
use http::{Request, Response};
use parking_lot::Mutex;
use serde_json::{Value, json};

const FIXTURES: [(&str, &str); 3] = [
    (
        include_str!("fixtures/kimi/chat-completions.json"),
        include_str!("fixtures/kimi/chat-completions.sse"),
    ),
    (
        include_str!("fixtures/kimi/responses.json"),
        include_str!("fixtures/kimi/responses.sse"),
    ),
    (
        include_str!("fixtures/kimi/messages.json"),
        include_str!("fixtures/kimi/messages.sse"),
    ),
];

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

struct KimiScenario {
    sink: Arc<RecordingSink>,
    hook: HarnessUsageHook<Arc<RecordingSink>>,
}

impl KimiScenario {
    fn new(policy: HooksConfig) -> Self {
        let sink = Arc::new(RecordingSink::default());
        let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::new(policy),
            Arc::clone(&sink),
        );
        Self { sink, hook }
    }

    async fn exchange(&self, host: &str, path: &str, request: &Value, response: &str) {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::TlsHttp {
                server_name: host.to_owned(),
            },
            None,
        );
        let exchange = HttpExchange::new(
            flow,
            Request::builder()
                .method("POST")
                .uri(path)
                .header("host", host)
                .header("user-agent", "deepseek-harness/0.2.0-rc.2")
                .header("x-deepseek-harness-session-id", "dsh-kimi-session")
                .body(CapturedBody::from_bytes(
                    request.to_string().into_bytes().into(),
                ))
                .unwrap(),
            Response::builder()
                .header(
                    "content-type",
                    if response.starts_with("data:") || response.starts_with("event:") {
                        "text/event-stream"
                    } else {
                        "application/json"
                    },
                )
                .body(CapturedBody::from_bytes(
                    response.as_bytes().to_vec().into(),
                ))
                .unwrap(),
        );
        self.hook.on_http_exchange(&exchange).await.unwrap();
    }
}

#[tokio::test]
async fn kimi_protocols_preserve_thinking_tool_roundtrip_and_disjoint_cache_usage() {
    for host in ["api.moonshot.cn", "api.moonshot.ai", "kimi.gateway.example"] {
        for (fixture, stream) in FIXTURES {
            let fixture: Value = serde_json::from_str(fixture).unwrap();
            let path = fixture["path"].as_str().unwrap();
            for response in [stream.to_owned(), fixture["response"].to_string()] {
                let scenario = KimiScenario::new(HooksConfig::default());
                scenario
                    .exchange(host, path, &fixture["request"], &response)
                    .await;
                scenario
                    .exchange(
                        host,
                        path,
                        &fixture["followup"],
                        &fixture["reply"].to_string(),
                    )
                    .await;
                let events = scenario.sink.events.lock();
                assert_eq!(events.len(), 4, "{host}{path}");
                for event in &*events {
                    assert_eq!(event.agent.name, "deepseek-harness");
                    assert_eq!(event.llm.provider.wire_name(), host);
                    assert_eq!(event.llm.model, "kimi-k3");
                    assert_eq!(event.session_id, "dsh-kimi-session");
                    assert_eq!(
                        event.conversation.as_ref().unwrap().completeness,
                        ContentCompleteness::Complete
                    );
                }
                for (index, input, total) in [(0, 10, 112), (2, 30, 132)] {
                    assert_eq!(events[index].token_usage.input_tokens, input);
                    assert_eq!(events[index].token_usage.cache_read_tokens, 60);
                    assert_eq!(events[index].token_usage.cache_write_tokens, 30);
                    assert_eq!(events[index + 1].token_usage.output_tokens, 12);
                    assert_eq!(
                        events[index].token_usage.total_tokens
                            + events[index + 1].token_usage.total_tokens,
                        total
                    );
                }
                assert_eq!(
                    events[1].token_usage.reasoning_tokens,
                    if path.ends_with("/chat/completions") {
                        0
                    } else {
                        5
                    }
                );
                let thinking = &events[1].conversation.as_ref().unwrap().messages[0];
                assert_eq!(thinking.role, MessageRole::Reasoning);
                assert_eq!(thinking.text, "Read the file.");
                assert_eq!(events[1].tool_calls.len(), 1);
                let call = &events[1].tool_calls[0];
                assert_eq!(call.call_id, "kimi-call-1");
                assert_eq!(call.name, "read");
                assert_eq!(
                    serde_json::from_str::<Value>(&call.input).unwrap(),
                    json!({"path": "probe.txt"})
                );
                assert_eq!(events[2].tool_results.len(), 1);
                assert_eq!(events[2].tool_results[0].call_id, call.call_id);
                assert_eq!(events[2].tool_results[0].output, "KIMI_PROBE_OK");
                let history = &events[2].conversation.as_ref().unwrap().messages;
                assert!(history.iter().any(|message| {
                    message.role == MessageRole::Reasoning && message.text == "Read the file."
                }));
                let reply = &events[3].conversation.as_ref().unwrap().messages;
                assert!(reply.iter().any(|message| {
                    message.role == MessageRole::Assistant && message.text == "KIMI_PROBE_OK"
                }));
                assert_ne!(events[0].event_id, events[2].event_id);
            }
        }
    }
}

#[tokio::test]
async fn kimi_content_off_keeps_usage_without_thinking_tools_or_text() {
    let policy: HooksConfig = serde_json::from_value(json!({
        "harness_usage": {"enabled": true, "config": {"content": {
            "token_usage": true, "conversation_text": false, "tool_calls": false, "images": false
        }}}
    }))
    .unwrap();
    for (fixture, stream) in FIXTURES {
        let fixture: Value = serde_json::from_str(fixture).unwrap();
        let scenario = KimiScenario::new(policy.clone());
        scenario
            .exchange(
                "api.moonshot.cn",
                fixture["path"].as_str().unwrap(),
                &fixture["request"],
                stream,
            )
            .await;
        let events = scenario.sink.events.lock();
        assert_eq!(events.len(), 2);
        for event in &*events {
            assert!(event.text.is_none());
            assert!(event.tool_calls.is_empty());
            assert!(event.tool_results.is_empty());
            assert!(event.attachments.is_empty());
            let conversation = event.conversation.as_ref().unwrap();
            assert!(conversation.policy_omitted);
            assert!(conversation.messages.is_empty());
        }
        assert_eq!(events[0].token_usage.input_tokens, 10);
        assert_eq!(events[0].token_usage.cache_read_tokens, 60);
        assert_eq!(events[0].token_usage.cache_write_tokens, 30);
        assert_eq!(events[1].token_usage.output_tokens, 12);
    }
}
