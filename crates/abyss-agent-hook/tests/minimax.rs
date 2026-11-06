//! `MiniMax` compatible APIs through the public Agent Hook boundary.
//! Credential-free fixtures cover reasoning, cache accounting, and tool roundtrips.

use std::{convert::Infallible, future::Future, net::SocketAddr, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, DeviceIdentity, HarnessUsageHook, HarnessUsageHookConfig, HooksConfig,
    HooksRuntimeConfig,
};
use abyss_mitm::{
    CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, TransparentProtocol,
};
use abyss_plugin_protocol::event::{
    AgentEvent, ContentCategory, ContentCompleteness, ConversationEntry, EntryRole,
};
use http::{Request, Response};
use parking_lot::Mutex;
use serde_json::{Value, json};

const FIXTURES: [(&str, &str); 3] = [
    (
        include_str!("fixtures/minimax/chat-completions.json"),
        include_str!("fixtures/minimax/chat-completions.sse"),
    ),
    (
        include_str!("fixtures/minimax/responses.json"),
        include_str!("fixtures/minimax/responses.sse"),
    ),
    (
        include_str!("fixtures/minimax/messages.json"),
        include_str!("fixtures/minimax/messages.sse"),
    ),
];

/// The entries of one role, in order.
fn entries(entries: &[ConversationEntry], role: EntryRole) -> Vec<&ConversationEntry> {
    entries.iter().filter(|entry| entry.role == role).collect()
}

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

struct MiniMaxScenario {
    sink: Arc<RecordingSink>,
    hook: HarnessUsageHook<Arc<RecordingSink>>,
}

impl MiniMaxScenario {
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
                .header("x-deepseek-harness-session-id", "dsh-minimax-session")
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
async fn minimax_protocols_preserve_thinking_tool_roundtrip_and_disjoint_cache_usage() {
    for host in [
        "api.minimax.cn",
        "api.minimax.io",
        "api.minimaxi.com",
        "minimax.gateway.example",
    ] {
        for (fixture, stream) in FIXTURES {
            let fixture: Value = serde_json::from_str(fixture).unwrap();
            let path = fixture["path"].as_str().unwrap();
            for response in [stream.to_owned(), fixture["response"].to_string()] {
                let scenario = MiniMaxScenario::new(HooksConfig::default());
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
                    assert_eq!(event.llm.model, "MiniMax-M3.1-Flash");
                    assert_eq!(event.session_id, "dsh-minimax-session");
                    assert_eq!(
                        event.conversation.as_ref().unwrap().completeness,
                        ContentCompleteness::Complete
                    );
                }
                for (index, input, total) in [(0, 40, 112), (2, 60, 132)] {
                    assert_eq!(events[index].token_usage.input_tokens, input);
                    assert_eq!(events[index].token_usage.cache_read_tokens, 60);
                    assert_eq!(events[index].token_usage.cache_write_tokens, 0);
                    assert_eq!(events[index + 1].token_usage.output_tokens, 12);
                    assert_eq!(
                        events[index].token_usage.total_tokens
                            + events[index + 1].token_usage.total_tokens,
                        total
                    );
                }
                assert_eq!(events[1].token_usage.reasoning_tokens, 5);
                let response = &events[1].conversation.as_ref().unwrap().entries;
                assert_eq!(response[0].role, EntryRole::Reasoning);
                assert_eq!(response[0].text, "Read the file.");
                let calls = entries(response, EntryRole::ToolCall);
                assert_eq!(calls.len(), 1);
                let call = calls[0];
                assert_eq!(call.call_id.as_deref(), Some("minimax-call-1"));
                assert_eq!(call.name.as_deref(), Some("read"));
                assert_eq!(
                    serde_json::from_str::<Value>(&call.text).unwrap(),
                    json!({"path": "probe.txt"})
                );
                let history = &events[2].conversation.as_ref().unwrap().entries;
                let results = entries(history, EntryRole::ToolResult);
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].call_id, call.call_id);
                assert_eq!(results[0].text, "MINIMAX_PROBE_OK");
                assert!(
                    entries(history, EntryRole::Reasoning)
                        .iter()
                        .any(|entry| entry.text == "Read the file.")
                );
                let reply = &events[3].conversation.as_ref().unwrap().entries;
                assert!(
                    entries(reply, EntryRole::Assistant)
                        .iter()
                        .any(|entry| entry.text == "MINIMAX_PROBE_OK")
                );
                assert_ne!(events[0].event_id, events[2].event_id);
            }
        }
    }
}

#[tokio::test]
async fn minimax_content_off_keeps_usage_and_roles_without_thinking_tools_or_text() {
    let policy: HooksConfig = serde_json::from_value(json!({
        "harness_usage": {"enabled": true, "config": {"content": {
            "token_usage": true, "conversation_text": false, "tool_calls": false, "images": false
        }}}
    }))
    .unwrap();
    for (fixture, stream) in FIXTURES {
        let fixture: Value = serde_json::from_str(fixture).unwrap();
        let scenario = MiniMaxScenario::new(policy.clone());
        scenario
            .exchange(
                "api.minimax.cn",
                fixture["path"].as_str().unwrap(),
                &fixture["request"],
                stream,
            )
            .await;
        scenario
            .exchange(
                "api.minimax.cn",
                fixture["path"].as_str().unwrap(),
                &fixture["followup"],
                &fixture["reply"].to_string(),
            )
            .await;
        let events = scenario.sink.events.lock();
        assert_eq!(events.len(), 4);
        for event in &*events {
            assert!(event.attachments.is_empty());
            assert_eq!(
                event.omitted,
                [
                    ContentCategory::ConversationText,
                    ContentCategory::ToolContent,
                    ContentCategory::Images,
                ]
            );
            let conversation = event.conversation.as_ref().unwrap();
            assert!(
                conversation
                    .entries
                    .iter()
                    .all(|entry| entry.text.is_empty())
            );
        }
        assert_eq!(events[0].token_usage.input_tokens, 40);
        assert_eq!(events[0].token_usage.cache_read_tokens, 60);
        assert_eq!(events[0].token_usage.cache_write_tokens, 0);
        assert_eq!(events[1].token_usage.output_tokens, 12);
        assert_eq!(events[2].token_usage.input_tokens, 60);
        assert_eq!(events[3].token_usage.output_tokens, 12);
    }
}
