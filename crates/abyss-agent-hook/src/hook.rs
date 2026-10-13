//! Single coordinator for Harness detection, protocol parsing, and delivery.

use std::sync::Arc;

use abyss_mitm::{FlowContext, HookError, HookFuture, HttpExchange, MitmHook, WebSocketMessage};
use abyss_plugin_protocol::event::LlmProvider;
use http::{HeaderMap, header::HOST};

use crate::{
    config::{HarnessUsageHookConfig, HooksRuntimeConfig},
    delivery::{AgentEventSink, EventDelivery},
    event::{NormalizableExchange, NormalizedUsageEvent, normalize_exchange},
    harness::{HarnessDetection, HarnessRegistry},
    protocol::{
        AnthropicProtocol, ClaudeWebProtocol, LlmProtocol, OpenAiProtocol, ProtocolDetector,
        anthropic::{
            ClaudeWebContext, parse_anthropic_messages_exchange, parse_claude_web_exchange,
        },
        openai::{
            OpenAiWebSocketAccumulator, parse_openai_exchange, parse_openai_websocket_message,
        },
    },
    provider::ProviderResolver,
};

/// Broker Hook that owns the complete Harness usage pipeline.
pub struct HarnessUsageHook<S>
where
    S: AgentEventSink,
{
    config: Arc<HarnessUsageHookConfig>,
    runtime_config: HooksRuntimeConfig,
    delivery: EventDelivery<S>,
    claude_web_context: ClaudeWebContext,
    openai_websocket: OpenAiWebSocketAccumulator,
}

impl<S> HarnessUsageHook<S>
where
    S: AgentEventSink,
{
    /// Creates the unified pipeline with shared policy and event delivery.
    #[must_use]
    pub fn with_runtime_config_and_event_sink(
        config: HarnessUsageHookConfig,
        runtime_config: HooksRuntimeConfig,
        sink: S,
    ) -> Self {
        Self {
            config: Arc::new(config),
            runtime_config,
            delivery: EventDelivery::new(sink),
            claude_web_context: ClaudeWebContext::default(),
            openai_websocket: OpenAiWebSocketAccumulator::default(),
        }
    }

    fn http_events(&self, exchange: &HttpExchange) -> Vec<NormalizedUsageEvent> {
        let policy = self.runtime_config.snapshot();
        let Some(detection) = HarnessRegistry::detect_http(exchange, &policy.harness_usage.config)
        else {
            return Vec::new();
        };
        if self.claude_web_context.record_upload(exchange) {
            return Vec::new();
        }
        let Some(protocol) = ProtocolDetector::detect_http(exchange) else {
            return Vec::new();
        };
        let provider = ProviderResolver::resolve(&http_host(exchange), protocol);
        let content = policy
            .harness_usage
            .config
            .content_for_harness(detection.harness_id.as_str());

        match protocol {
            LlmProtocol::OpenAi(OpenAiProtocol::Responses | OpenAiProtocol::ChatCompletions) => {
                parse_openai_exchange(exchange)
                    .map(|parsed| self.normalize(&parsed, &content, &detection, &provider))
            }
            LlmProtocol::Anthropic(AnthropicProtocol::Messages) => {
                parse_anthropic_messages_exchange(exchange)
                    .map(|parsed| self.normalize(&parsed, &content, &detection, &provider))
            }
            LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(
                ClaudeWebProtocol::ConversationCompletion,
            )) => parse_claude_web_exchange(exchange).map(|mut parsed| {
                self.claude_web_context
                    .attach_referenced_images(&mut parsed);
                self.normalize(&parsed, &content, &detection, &provider)
            }),
        }
        .unwrap_or_default()
    }

    fn normalize<E>(
        &self,
        parsed: &E,
        content: &crate::config::HarnessUsageContentConfig,
        detection: &HarnessDetection,
        provider: &LlmProvider,
    ) -> Vec<NormalizedUsageEvent>
    where
        E: NormalizableExchange,
    {
        normalize_exchange(&self.config, parsed, content, detection, provider)
    }

    fn websocket_events(&self, message: &WebSocketMessage) -> Vec<NormalizedUsageEvent> {
        let policy = self.runtime_config.snapshot();
        let Some(detection) =
            HarnessRegistry::detect_websocket(message, &policy.harness_usage.config)
        else {
            return Vec::new();
        };
        let Some(protocol @ LlmProtocol::OpenAi(OpenAiProtocol::Responses)) =
            ProtocolDetector::detect_websocket(message)
        else {
            return Vec::new();
        };
        let content = policy
            .harness_usage
            .config
            .content_for_harness(detection.harness_id.as_str());
        let frame = parse_openai_websocket_message(message);
        let Some(parsed) = self.openai_websocket.push(&message.flow.flow_id, frame) else {
            return Vec::new();
        };
        let provider = ProviderResolver::resolve(&websocket_host(message), protocol);
        self.normalize(&parsed, &content, &detection, &provider)
    }
}

impl<S> MitmHook for HarnessUsageHook<S>
where
    S: AgentEventSink,
{
    fn enabled(&self) -> bool {
        self.runtime_config.snapshot().harness_usage.enabled
    }

    fn matches(&self, _flow: &FlowContext) -> bool {
        self.enabled()
    }

    fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
        let events = self.http_events(exchange);
        Box::pin(async move {
            self.delivery
                .deliver(events)
                .await
                .map_err(|error| HookError::failed(error.to_string()))
        })
    }

    fn on_websocket_message<'a>(&'a self, message: &'a WebSocketMessage) -> HookFuture<'a> {
        let events = self.websocket_events(message);
        Box::pin(async move {
            self.delivery
                .deliver(events)
                .await
                .map_err(|error| HookError::failed(error.to_string()))
        })
    }
}

fn http_host(exchange: &HttpExchange) -> String {
    request_host(
        exchange.request.headers(),
        exchange.request.uri(),
        exchange.flow.destination_host.as_deref(),
    )
}

fn websocket_host(message: &WebSocketMessage) -> String {
    request_host(
        message.upgrade_request.headers(),
        message.upgrade_request.uri(),
        message.flow.destination_host.as_deref(),
    )
}

fn request_host(headers: &HeaderMap, uri: &http::Uri, destination: Option<&str>) -> String {
    uri.host()
        .or_else(|| headers.get(HOST).and_then(|value| value.to_str().ok()))
        .or(destination)
        .unwrap_or("unknown")
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::{
        convert::Infallible,
        future::Future,
        net::SocketAddr,
        sync::{Arc, Mutex},
    };

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, MitmHook, OriginalDestination, SourceProcess,
        TransparentProtocol,
    };
    use abyss_plugin_protocol::event::{AgentEvent, ContentCompleteness, MessageRole};
    use http::{Request, Response};

    use crate::{
        AgentEventSink, DeviceIdentity, HarnessUsageHookConfig, HooksConfig, HooksRuntimeConfig,
    };

    use super::HarnessUsageHook;

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: Mutex<Vec<AgentEvent>>,
    }

    impl AgentEventSink for RecordingSink {
        type Error = Infallible;

        fn publish(
            &self,
            event: AgentEvent,
        ) -> impl Future<Output = Result<(), Self::Error>> + Send {
            self.events.lock().unwrap().push(event);
            std::future::ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn custom_harness_reuses_protocol_and_gateway_provider() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));

        hook.on_http_exchange(&openai_exchange("acme-agent"))
            .await
            .unwrap();

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "acme-agent"));
        assert!(
            events
                .iter()
                .all(|event| { event.llm.provider.wire_name() == "gateway.example" })
        );
        drop(events);
    }

    #[tokio::test]
    async fn projects_http_messages_and_skips_exchanges_without_response_content() {
        let request = b" {\"model\":\"gpt-test\",\"input\":[{\"role\":\"developer\",\"content\":\"instructions\"},{\"role\":\"user\",\"content\":\"continue\"},{\"role\":\"user\",\"content\":\"continue\"}],\"tools\":[{\"name\":\"exec\",\"schema\":{\"unknown\":42}}],\"extra\": [1,1]} \n";
        let response = b"event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\r\n\r\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"unknown\":true}}\r\n\r\ndata: [DONE]\r\n\r\n";
        for (response, expected_events) in [
            (response.as_slice(), 2),
            (
                b"{\"error\":{\"code\":\"overloaded\",\"details\": [1,2]}}\n",
                0,
            ),
            (b"\xff\0\x80", 0),
        ] {
            let sink = Arc::new(RecordingSink::default());
            let hook = hook(Arc::clone(&sink));
            let mut exchange = openai_exchange("acme-agent");
            *exchange.request.body_mut() = CapturedBody::from_bytes(request.to_vec().into());
            *exchange.response.body_mut() = CapturedBody::from_bytes(response.to_vec().into());
            hook.on_http_exchange(&exchange).await.unwrap();
            let events = sink.events.lock().unwrap();
            assert_eq!(events.len(), expected_events);
            if expected_events == 0 {
                continue;
            }
            let request = events[0].conversation.as_ref().unwrap();
            assert_eq!(
                request
                    .messages
                    .iter()
                    .map(|message| (message.role, message.text.as_str()))
                    .collect::<Vec<_>>(),
                vec![
                    (MessageRole::Developer, "instructions"),
                    (MessageRole::User, "continue"),
                    (MessageRole::User, "continue"),
                ]
            );
            let reply = events[1].conversation.as_ref().unwrap();
            assert_eq!(reply.messages.len(), 1);
            assert_eq!(reply.messages[0].role, MessageRole::Assistant);
            assert_eq!(reply.messages[0].text, "hi");
            assert_eq!(reply.completeness, ContentCompleteness::Complete);
            assert_eq!(events[1].text.as_deref(), Some("hi"));
            drop(events);
        }
    }

    #[tokio::test]
    async fn identical_observations_produce_identical_event_ids() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let exchange = openai_exchange("acme-agent");
        hook.on_http_exchange(&exchange).await.unwrap();
        hook.on_http_exchange(&exchange).await.unwrap();
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 4);
        assert_ne!(events[0].event_id, events[1].event_id);
        assert_eq!(events[0].event_id, events[2].event_id);
        assert_eq!(events[1].event_id, events[3].event_id);
        assert_eq!(
            serde_json::to_value(&events[0].conversation).unwrap(),
            serde_json::to_value(&events[2].conversation).unwrap()
        );
        drop(events);
    }

    #[tokio::test]
    async fn websocket_assembles_turn_and_marks_failed_server_frames_partial() {
        use abyss_mitm::{WebSocketDirection, WebSocketMessage};
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let exchange = openai_exchange("acme-agent");
        let (parts, _) = exchange.request.into_parts();
        let upgrade = Request::from_parts(parts, ());
        let request = " {\"type\":\"response.create\",\"response\":{\"model\":\"test\",\"input\":[{\"role\":\"user\",\"content\":\"hello\"}]}}\n";
        let created = "{\"type\":\"response.created\",\"response\":{\"id\":\"resp-1\"}}";
        let delta = "{\"type\":\"response.output_text.delta\",\"output_index\":0,\"content_index\":0,\"delta\":\"hi\"}";
        let terminal = "{\"type\":\"response.completed\",\"response\":{\"id\":\"resp-1\",\"output\":[{\"id\":\"msg-1\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"hi there\"}]}],\"usage\":{\"input_tokens\":1,\"output_tokens\":2,\"total_tokens\":3}}}";
        for (sequence, direction, body) in [
            (1, WebSocketDirection::ClientToServer, request),
            (2, WebSocketDirection::ServerToClient, created),
            (3, WebSocketDirection::ServerToClient, "{broken"),
            (4, WebSocketDirection::ServerToClient, delta),
            (5, WebSocketDirection::ServerToClient, terminal),
        ] {
            hook.on_websocket_message(&WebSocketMessage::new(
                exchange.flow.clone(),
                upgrade.clone(),
                direction,
                sequence,
                Some(body.to_owned()),
                None,
            ))
            .await
            .unwrap();
        }
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        let request_content = events[0].conversation.as_ref().unwrap();
        assert_eq!(request_content.messages[0].role, MessageRole::User);
        assert_eq!(request_content.messages[0].text, "hello");
        assert_eq!(request_content.completeness, ContentCompleteness::Complete);
        let response_content = events[1].conversation.as_ref().unwrap();
        assert_eq!(response_content.messages.len(), 1);
        assert_eq!(response_content.messages[0].id.as_deref(), Some("msg-1"));
        assert_eq!(response_content.messages[0].text, "hi there");
        assert_eq!(response_content.completeness, ContentCompleteness::Partial);
        assert_eq!(events[1].text.as_deref(), Some("hi there"));
        drop(events);
    }

    #[tokio::test]
    async fn truncated_but_parseable_response_reports_partial() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let mut exchange = anthropic_exchange("acme-agent");
        *exchange.response.body_mut() = CapturedBody::from_truncated_bytes(
            concat!(
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",",
                "\"usage\":{\"input_tokens\":3}}}\n\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":",
                "{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":"
            )
            .as_bytes()
            .to_vec()
            .into(),
        );
        hook.on_http_exchange(&exchange).await.unwrap();
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        let request = events[0].conversation.as_ref().unwrap();
        assert_eq!(request.completeness, ContentCompleteness::Complete);
        let reply = events[1].conversation.as_ref().unwrap();
        assert_eq!(reply.completeness, ContentCompleteness::Partial);
        assert_eq!(reply.messages[0].text, "hi");
        assert_eq!(events[1].text.as_deref(), Some("hi"));
        drop(events);
    }

    #[tokio::test]
    async fn protocol_shape_without_harness_evidence_produces_no_event() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));

        hook.on_http_exchange(&openai_exchange("ordinary-sdk"))
            .await
            .unwrap();

        assert!(sink.events.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn custom_harness_reuses_anthropic_messages_protocol() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));

        hook.on_http_exchange(&anthropic_exchange("acme-agent"))
            .await
            .unwrap();

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "acme-agent"));
        assert!(
            events
                .iter()
                .all(|event| event.llm.provider.wire_name() == "anthropic")
        );
        drop(events);
    }

    #[tokio::test]
    async fn claude_code_turns_follow_the_billing_turn_index() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let header = |fields: &str| {
            serde_json::json!([{
                "type": "text",
                "text": format!("x-anthropic-billing-header: cc_version=2.1.293.af3; cc_entrypoint=cli; {fields}")
            }])
        };
        let requests = [
            // Main loop: `continue` that failed with `thread_not_found`, its
            // `create` replay under a new prompt id, then a tool-result-only
            // `continue`.
            serde_json::json!({
                "system": header("cc_prompt_id=p1; cc_prompt_index=13; cc_turn_index=13;"),
                "messages": [{"role": "user", "content": "look at the thread field"}],
                "thread": {"type": "continue", "previous_message_id": "msg_1"}
            }),
            serde_json::json!({
                "system": header("cc_prompt_id=p2; cc_prompt_index=13; cc_turn_index=13;"),
                "messages": [
                    {"role": "user", "content": "earlier prompt"},
                    {"role": "assistant", "content": "earlier answer"},
                    {"role": "user", "content": "look at the thread field"}
                ],
                "thread": {"type": "create"}
            }),
            serde_json::json!({
                "system": header("cc_prompt_id=p2; cc_prompt_index=13; cc_turn_index=13;"),
                "messages": [{"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}
                ]}],
                "thread": {"type": "continue", "previous_message_id": "msg_2"}
            }),
            // Subagent, side request, and a quota probe without a header.
            serde_json::json!({
                "system": header("cc_is_subagent=true; cc_prompt_id=p2;"),
                "messages": [{"role": "user", "content": "explore the repo"}],
                "thread": {"type": "create"}
            }),
            serde_json::json!({
                "system": header("cc_prev_req=req_1;"),
                "messages": [{"role": "user", "content": "Recap in under 40 words."}]
            }),
            serde_json::json!({"messages": [{"role": "user", "content": "quota"}]}),
        ];
        for request in &requests {
            hook.on_http_exchange(&anthropic_exchange_with_request("claude", request))
                .await
                .unwrap();
        }

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), requests.len() * 2);
        let expected_turns = [
            Some("cc_turn:13"),
            Some("cc_turn:13"),
            Some("cc_turn:13"),
            None,
            None,
            None,
        ];
        for ((exchange_events, request), expected_turn) in
            events.chunks(2).zip(&requests).zip(expected_turns)
        {
            for event in exchange_events {
                assert_eq!(event.agent.name, "claude-code");
                assert_eq!(event.turn_id.as_deref(), expected_turn);
                assert_eq!(
                    event.claude_thread.clone().map(serde_json::Value::Object),
                    request.get("thread").cloned()
                );
                assert_eq!(
                    event.claude_code_billing.is_some(),
                    request.get("system").is_some()
                );
            }
        }
        let billing = events[0].claude_code_billing.as_ref().unwrap();
        assert_eq!(billing["cc_prompt_id"], "p1");
        assert_eq!(billing["cc_turn_index"], "13");
        assert_eq!(
            events[7].claude_code_billing.as_ref().unwrap()["cc_is_subagent"],
            "true"
        );
        drop(events);
    }

    #[tokio::test]
    async fn other_anthropic_clients_carry_no_turn_id() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let request = serde_json::json!({
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi"},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "ok"}
                ]}
            ]
        });

        hook.on_http_exchange(&anthropic_exchange("acme-agent"))
            .await
            .unwrap();
        hook.on_http_exchange(&anthropic_exchange_with_request("acme-agent", &request))
            .await
            .unwrap();

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 4);
        assert!(events.iter().all(|event| event.turn_id.is_none()));
        assert!(
            events
                .iter()
                .all(|event| event.claude_code_billing.is_none())
        );
        drop(events);
    }

    fn hook(sink: Arc<RecordingSink>) -> HarnessUsageHook<Arc<RecordingSink>> {
        let config = serde_json::from_value::<HooksConfig>(serde_json::json!({
            "harness_usage": {"config": {"harnesses": {"acme-agent": {
                "enabled": true,
                "matchers": [{"process_names": ["acme-agent"]}]
            }}}}
        }))
        .unwrap();
        HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::new(config),
            sink,
        )
    }

    fn openai_exchange(process_name: &str) -> HttpExchange {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(SourceProcess::new(
                Some(42),
                Some(process_name.to_owned()),
                None,
            )),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("host", "gateway.example")
            .header("content-type", "application/json")
            .body(CapturedBody::from_bytes(
                serde_json::to_vec(&serde_json::json!({
                    "model": "gpt-test",
                    "input": [{"role": "user", "content": "hello"}]
                }))
                .unwrap()
                .into(),
            ))
            .unwrap();
        let response = Response::builder()
            .header("content-type", "application/json")
            .body(CapturedBody::from_bytes(
                serde_json::to_vec(&serde_json::json!({
                    "id": "resp-test",
                    "model": "gpt-test",
                    "output": [{"content": [{"type": "output_text", "text": "hi"}]}],
                    "usage": {"input_tokens": 1_i32, "output_tokens": 1_i32, "total_tokens": 2_i32}
                }))
                .unwrap()
                .into(),
            ))
            .unwrap();
        HttpExchange::new(flow, request, response)
    }

    fn anthropic_exchange(process_name: &str) -> HttpExchange {
        anthropic_exchange_with_request(
            process_name,
            &serde_json::json!({
                "model": "claude-test",
                "messages": [{"role": "user", "content": "hello"}]
            }),
        )
    }

    fn anthropic_exchange_with_request(
        process_name: &str,
        request_body: &serde_json::Value,
    ) -> HttpExchange {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(SourceProcess::new(
                Some(42),
                Some(process_name.to_owned()),
                None,
            )),
        );
        let request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("host", "api.anthropic.com")
            .header("content-type", "application/json")
            .header("x-claude-code-session-id", "session-1")
            .body(CapturedBody::from_bytes(
                serde_json::to_vec(request_body).unwrap().into(),
            ))
            .unwrap();
        let response = Response::builder()
            .header("content-type", "application/json")
            .body(CapturedBody::from_bytes(
                serde_json::to_vec(&serde_json::json!({
                    "id": "msg_test",
                    "model": "claude-test",
                    "content": [{"type": "text", "text": "hi"}],
                    "usage": {"input_tokens": 1_i32, "output_tokens": 1_i32}
                }))
                .unwrap()
                .into(),
            ))
            .unwrap();
        HttpExchange::new(flow, request, response)
    }
}
