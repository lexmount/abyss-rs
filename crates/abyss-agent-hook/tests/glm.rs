//! GLM-compatible wire fixtures exercised through the public Agent Hook boundary.
//! No provider credentials or live network are needed for these regressions.

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
use serde_json::json;

const REQUEST: &str = include_str!("fixtures/glm/request.json");
const STREAM: &str = include_str!("fixtures/glm/response.sse");
const FOLLOWUP: &str = include_str!("fixtures/glm/followup.json");
const RESPONSE: &str = include_str!("fixtures/glm/response.json");

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

struct GlmScenario {
    sink: Arc<RecordingSink>,
    hook: HarnessUsageHook<Arc<RecordingSink>>,
}

impl GlmScenario {
    fn new(policy: HooksConfig) -> Self {
        let sink = Arc::new(RecordingSink::default());
        let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::new(policy),
            Arc::clone(&sink),
        );
        Self { sink, hook }
    }

    async fn exchange(&self, host: &str, path: &str, request: &str, response: &str) {
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
                .header("x-deepseek-harness-session-id", "dsh-glm-session")
                .body(CapturedBody::from_bytes(request.as_bytes().to_vec().into()))
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
async fn glm_responses_preserves_reasoning_tools_usage_and_session_without_done_sentinel() {
    let scenario = GlmScenario::new(HooksConfig::default());
    let request = json!({
        "model":"glm-4.7", "stream":true,
        "input":[{"role":"user","content":"Read probe.txt."}]
    });
    scenario
        .exchange(
            "open.bigmodel.cn",
            "/api/v1/responses",
            &request.to_string(),
            include_str!("fixtures/glm/responses.sse"),
        )
        .await;
    let events = scenario.sink.events.lock();
    assert_eq!(events.len(), 2);
    for event in &*events {
        assert_eq!(event.agent.name, "deepseek-harness");
        assert_eq!(event.llm.provider.wire_name(), "open.bigmodel.cn");
        assert_eq!(event.llm.model, "glm-4.7");
        assert_eq!(event.session_id, "dsh-glm-session");
        assert_eq!(
            event.conversation.as_ref().unwrap().completeness,
            ContentCompleteness::Complete
        );
    }
    assert_eq!(events[0].token_usage.input_tokens, 20);
    assert_eq!(events[0].token_usage.cache_read_tokens, 80);
    assert_eq!(events[1].token_usage.output_tokens, 12);
    assert_eq!(events[1].token_usage.reasoning_tokens, 5);
    let messages = &events[1].conversation.as_ref().unwrap().messages;
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].role, MessageRole::Reasoning);
    assert_eq!(messages[0].text, "Read the file.");
    assert_eq!(messages[1].role, MessageRole::Tool);
    assert_eq!(events[1].tool_calls.len(), 1);
    assert_eq!(events[1].tool_calls[0].call_id, "call_glm");
    assert_eq!(events[1].tool_calls[0].name, "read_file");
    assert_eq!(events[1].tool_calls[0].input, r#"{"path":"probe.txt"}"#);
}

#[tokio::test]
async fn dsh_glm_stream_and_tool_followup_preserve_provider_session_and_content() {
    for host in ["open.bigmodel.cn", "api.z.ai", "glm.gateway.example"] {
        for path in [
            "/api/paas/v4/chat/completions",
            "/api/coding/paas/v4/chat/completions",
        ] {
            let scenario = GlmScenario::new(HooksConfig::default());
            scenario.exchange(host, path, REQUEST, STREAM).await;
            scenario.exchange(host, path, FOLLOWUP, RESPONSE).await;
            let events = scenario.sink.events.lock();
            assert_eq!(events.len(), 4, "{host}{path}");
            for event in &*events {
                assert_eq!(event.agent.name, "deepseek-harness");
                assert_eq!(event.llm.provider.wire_name(), host);
                assert_eq!(event.llm.model, "glm-4.7");
                assert_eq!(event.session_id, "dsh-glm-session");
                assert_eq!(
                    event.conversation.as_ref().unwrap().completeness,
                    ContentCompleteness::Complete
                );
            }
            assert_eq!(events[0].token_usage.input_tokens, 20);
            assert_eq!(events[0].token_usage.cache_read_tokens, 80);
            assert_eq!(events[1].token_usage.output_tokens, 12);
            assert_eq!(events[1].token_usage.reasoning_tokens, 5);
            assert_eq!(
                events[0].token_usage.total_tokens + events[1].token_usage.total_tokens,
                112
            );
            assert_eq!(events[1].tool_calls.len(), 1);
            assert_eq!(events[1].tool_calls[0].name, "read_file");
            assert_eq!(events[1].tool_calls[0].input, r#"{"path":"probe.txt"}"#);
            assert_eq!(events[2].tool_results.len(), 1);
            let messages = &events[2].conversation.as_ref().unwrap().messages;
            assert_eq!(messages[2].role, MessageRole::Reasoning);
            assert_eq!(messages[2].text, "I should read the file.");
            let reply = &events[3].conversation.as_ref().unwrap().messages;
            assert_eq!(reply[0].role, MessageRole::Reasoning);
            assert_eq!(reply[1].role, MessageRole::Assistant);
            assert_eq!(reply[1].text, "GLM_PROBE_OK");
            assert_eq!(events[3].token_usage.reasoning_tokens, 0);
            assert_ne!(events[0].event_id, events[2].event_id);
        }
    }
}

#[tokio::test]
async fn glm_content_off_retains_usage_without_thinking_tools_or_text() {
    let policy = serde_json::from_value(json!({
        "harness_usage": {"enabled": true, "config": {"content": {
            "token_usage": true, "conversation_text": false, "tool_calls": false, "images": false
        }}}
    }))
    .unwrap();
    let scenario = GlmScenario::new(policy);
    scenario
        .exchange(
            "open.bigmodel.cn",
            "/api/paas/v4/chat/completions",
            REQUEST,
            STREAM,
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
    assert_eq!(events[0].token_usage.cache_read_tokens, 80);
    assert_eq!(events[1].token_usage.output_tokens, 12);
}
