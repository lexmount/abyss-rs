//! Single coordinator for Harness detection, protocol parsing, and delivery.

use std::sync::Arc;

use abyss_mitm::{FlowContext, HookError, HookFuture, HttpExchange, MitmHook, WebSocketMessage};
use abyss_plugin_protocol::event::LlmProvider;
use http::{HeaderMap, header::HOST};

use crate::{
    config::{HarnessUsageHookConfig, HooksRuntimeConfig},
    delivery::{AgentEventSink, EventDelivery},
    event::{NormalizableExchange, NormalizedUsageEvent, normalize_exchange},
    harness::{AgentDeclaration, DeclarationSource, HarnessDetection, HarnessRegistry},
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
            LlmProtocol::OpenAi(protocol) => {
                parse_openai_exchange(exchange, protocol).map(|parsed| {
                    let declaration = http_declaration(
                        &detection,
                        exchange,
                        parsed.client_metadata.as_ref(),
                        &parsed.response_texts,
                    );
                    self.normalize(&parsed, &content, &detection, &provider, &declaration)
                })
            }
            LlmProtocol::Anthropic(AnthropicProtocol::Messages) => {
                parse_anthropic_messages_exchange(exchange).map(|parsed| {
                    let declaration =
                        http_declaration(&detection, exchange, None, &parsed.response_texts);
                    self.normalize(&parsed, &content, &detection, &provider, &declaration)
                })
            }
            LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(
                ClaudeWebProtocol::ConversationCompletion,
            )) => parse_claude_web_exchange(exchange).map(|mut parsed| {
                self.claude_web_context
                    .attach_referenced_images(&mut parsed);
                // The claude.ai completion protocol names its own turn.
                let declaration = AgentDeclaration {
                    turn_id: parsed.protocol_turn_id.clone(),
                    ..http_declaration(&detection, exchange, None, &parsed.response_texts)
                };
                self.normalize(&parsed, &content, &detection, &provider, &declaration)
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
        declaration: &AgentDeclaration,
    ) -> Vec<NormalizedUsageEvent>
    where
        E: NormalizableExchange,
    {
        if HarnessRegistry::requires_session(&detection.harness_id)
            && declaration.session_id.is_none()
        {
            tracing::debug!(
                harness = detection.harness_id.as_str(),
                "skipping request without a client session id"
            );
            return Vec::new();
        }
        normalize_exchange(
            &self.config,
            parsed,
            content,
            detection,
            provider,
            declaration,
        )
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
        // Frames after the upgrade carry no headers of their own.
        let declaration = HarnessRegistry::declare(
            &detection.harness_id,
            &DeclarationSource {
                headers: None,
                upgrade_headers: Some(message.upgrade_request.headers()),
                body: None,
                client_metadata: parsed.client_metadata.as_ref(),
                metadata: parsed.request_metadata.as_ref(),
                response_texts: &parsed.response_texts,
            },
        );
        self.normalize(&parsed, &content, &detection, &provider, &declaration)
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

/// What the detected Agent declared about one HTTP request.
fn http_declaration(
    detection: &HarnessDetection,
    exchange: &HttpExchange,
    client_metadata: Option<&serde_json::Value>,
    response_texts: &[String],
) -> AgentDeclaration {
    HarnessRegistry::declare(
        &detection.harness_id,
        &DeclarationSource {
            headers: Some(exchange.request.headers()),
            upgrade_headers: None,
            body: exchange.request.body().json(),
            client_metadata,
            metadata: exchange
                .request
                .body()
                .json()
                .and_then(|body| body.get("metadata")),
            response_texts,
        },
    )
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
    use abyss_plugin_protocol::event::{
        AgentEvent, ContentCompleteness, EventPurpose, MessageRole,
    };
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
    async fn builtin_deepseek_reuses_all_protocols_without_process_metadata_or_matchers() {
        let sink = Arc::new(RecordingSink::default());
        let hook = HarnessUsageHook::with_runtime_config_and_event_sink(
            HarnessUsageHookConfig::new(DeviceIdentity::new()),
            HooksRuntimeConfig::default_enabled(),
            Arc::clone(&sink),
        );
        let mut responses = openai_exchange("unused");
        responses.flow.source_process = None;
        responses
            .request
            .headers_mut()
            .insert("user-agent", "deepseek-harness/0.2.0-rc.2".parse().unwrap());
        hook.on_http_exchange(&responses).await.unwrap();

        let mut chat = openai_exchange("unused");
        chat.flow.source_process = None;
        *chat.request.uri_mut() = "/chat/completions".parse().unwrap();
        chat.request
            .headers_mut()
            .insert("user-agent", "deepseek-harness/0.2.0-rc.2".parse().unwrap());
        *chat.request.body_mut() = CapturedBody::from_bytes(
            br#"{"model":"compatible-chat","messages":[{"role":"user","content":"hello"}],"stream":true}"#.to_vec().into(),
        );
        chat.response
            .headers_mut()
            .insert("content-type", "text/event-stream".parse().unwrap());
        *chat.response.body_mut() = CapturedBody::from_bytes(
            concat!(
                "data: {\"id\":\"chat-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
                "data: {\"id\":\"chat-1\",\"choices\":[],\"usage\":{\"prompt_tokens\":7,\"completion_tokens\":2,\"total_tokens\":9}}\n\n",
                "data: [DONE]\n\n"
            ).as_bytes().to_vec().into(),
        );
        hook.on_http_exchange(&chat).await.unwrap();
        // An unrelated caller on the same protocol remains unmatched.
        chat.request.headers_mut().remove("user-agent");
        hook.on_http_exchange(&chat).await.unwrap();

        let mut anthropic = anthropic_exchange_with_headers(
            "unused",
            &[
                ("user-agent", "deepseek-harness/0.2.0-rc.2"),
                ("x-deepseek-harness-session-id", "dsh-session"),
            ],
            &serde_json::json!({
                "model": "compatible-messages",
                "messages": [{"role": "user", "content": "hello"}]
            }),
        );
        anthropic.flow.source_process = None;
        anthropic
            .request
            .headers_mut()
            .insert("host", "gateway.example".parse().unwrap());
        hook.on_http_exchange(&anthropic).await.unwrap();

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 6);
        assert!(
            events
                .iter()
                .all(|event| event.agent.name == "deepseek-harness")
        );
        assert!(
            events
                .iter()
                .all(|event| event.agent.version.as_deref() == Some("0.2.0-rc.2"))
        );
        assert!(
            events
                .iter()
                .all(|event| event.llm.provider.wire_name() == "gateway.example")
        );
        for pair in events.chunks(2) {
            assert_eq!(pair[0].text.as_deref(), Some("hello"));
            assert_eq!(pair[1].text.as_deref(), Some("hi"));
        }
        assert_eq!(events[2].token_usage.input_tokens, 7);
        assert_eq!(events[3].token_usage.output_tokens, 2);
        assert_eq!(events[4].session_id, "dsh-session");
        assert_eq!(events[5].session_id, "dsh-session");
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
    async fn websocket_prewarm_requires_explicit_false_and_does_not_leak_to_next_call() {
        use abyss_mitm::{WebSocketDirection, WebSocketMessage};
        use serde_json::{Value, json};

        for nested in [false, true] {
            for generate in [
                None,
                Some(json!(false)),
                Some(json!(true)),
                Some(json!("false")),
            ] {
                let sink = Arc::new(RecordingSink::default());
                let hook = hook(Arc::clone(&sink));
                let exchange = openai_exchange("acme-agent");
                let (parts, _) = exchange.request.into_parts();
                let upgrade = Request::from_parts(parts, ());
                let mut payload = json!({"model": "test", "instructions": "rules", "input": []});
                if let Some(value) = &generate {
                    payload["generate"] = value.clone();
                }
                let request = if nested {
                    json!({"type": "response.create", "response": payload})
                } else {
                    payload["type"] = json!("response.create");
                    payload
                };
                let terminal = json!({"type": "response.completed", "response": {
                    "id": "warm", "generate": false, "output": [],
                    "usage": {"input_tokens": 11_u64, "output_tokens": 0_u64, "total_tokens": 11_u64}
                }});
                let next_request = json!({"type": "response.create", "model": "test",
                    "previous_response_id": "warm",
                    "input": [{"role": "user", "content": "hello"}]});
                let next_terminal = json!({"type": "response.completed", "response": {
                    "id": "answer", "output": [{"id": "m1", "role": "assistant",
                        "content": [{"type": "output_text", "text": "hi"}]}],
                    "usage": {"input_tokens": 5_u64, "output_tokens": 2_u64, "total_tokens": 7_u64}
                }});
                for (sequence, direction, payload) in [
                    (1, WebSocketDirection::ClientToServer, request),
                    (2, WebSocketDirection::ServerToClient, terminal),
                    (3, WebSocketDirection::ClientToServer, next_request),
                    (4, WebSocketDirection::ServerToClient, next_terminal),
                ] {
                    hook.on_websocket_message(&WebSocketMessage::new(
                        exchange.flow.clone(),
                        upgrade.clone(),
                        direction,
                        sequence,
                        Some(payload.to_string()),
                        None,
                    ))
                    .await
                    .unwrap();
                }
                let events = sink.events.lock().unwrap();
                assert_eq!(events.len(), 3);
                let expected = (generate.as_ref().and_then(Value::as_bool) == Some(false))
                    .then_some(EventPurpose::Prewarm);
                assert_eq!(events[0].purpose, expected);
                assert_eq!(events[0].token_usage.input_tokens, 11);
                assert_eq!(
                    events[0].conversation.as_ref().unwrap().messages[0].text,
                    "rules"
                );
                assert!(events[1..].iter().all(|event| event.purpose.is_none()));
                assert_eq!(events[1].previous_response_id.as_deref(), Some("warm"));
                assert_eq!(events[1].token_usage.input_tokens, 5);
                assert_eq!(events[2].token_usage.output_tokens, 2);
                drop(events);
            }
        }
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
    async fn claude_code_declarations_follow_its_request_headers() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let user = |text: &str| serde_json::json!([{"role": "user", "content": text}]);
        let continue_from =
            |id: &str| serde_json::json!({"type": "continue", "previous_message_id": id});
        let requests = [
            // Main loop: `create`, then `continue`.
            (
                vec![("main", None, Some("p1"))],
                serde_json::json!({"messages": user("hello"), "thread": {"type": "create"}}),
            ),
            (
                vec![("main", None, Some("p1"))],
                serde_json::json!({"messages": user("next"), "thread": continue_from("msg_1")}),
            ),
            // Two subagents serving prompt p1.
            (
                vec![("subagent", Some("agent-a"), Some("p1"))],
                serde_json::json!({"messages": user("explore"), "thread": {"type": "create"}}),
            ),
            (
                vec![("subagent", Some("agent-b"), Some("p1"))],
                serde_json::json!({"messages": user("search"), "thread": continue_from("msg_b")}),
            ),
            // Auxiliary request, compaction, and a request without headers
            // whose billing header still names a prompt.
            (
                vec![("auxiliary", None, None)],
                serde_json::json!({"messages": user("Recap in under 40 words.")}),
            ),
            (
                vec![("compaction", None, None)],
                serde_json::json!({"messages": user("Summarize the conversation.")}),
            ),
            (
                Vec::new(),
                serde_json::json!({
                    "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_prompt_id=p9; cc_turn_index=9;"}],
                    "messages": user("quota")
                }),
            ),
        ];
        for (declared, request) in &requests {
            let mut headers = vec![("x-claude-code-session-id", "session-1")];
            for (class, agent, prompt) in declared {
                headers.push(("x-claude-code-request-class", class));
                headers.extend(agent.map(|agent| ("x-claude-code-agent-id", agent)));
                headers.extend(prompt.map(|prompt| ("x-claude-code-prompt-id", prompt)));
            }
            hook.on_http_exchange(&anthropic_exchange_with_headers(
                "claude", &headers, request,
            ))
            .await
            .unwrap();
        }

        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), requests.len() * 2);
        let expected = [
            (Some("p1"), Some("session-1"), None, None),
            (Some("p1"), Some("session-1"), Some("msg_1"), None),
            (Some("p1"), Some("agent-a"), None, None),
            (Some("p1"), Some("agent-b"), Some("msg_b"), None),
            (None, None, None, None),
            (None, None, None, Some(EventPurpose::Compaction)),
            (None, None, None, None),
        ];
        for (exchange_events, (turn, stream, previous, purpose)) in events.chunks(2).zip(expected) {
            for event in exchange_events {
                assert_eq!(event.agent.name, "claude-code");
                assert_eq!(event.turn_id.as_deref(), turn);
                assert_eq!(event.stream_id.as_deref(), stream);
                assert_eq!(event.previous_response_id.as_deref(), previous);
                assert_eq!(event.purpose, purpose);
                assert_eq!(event.response_id.as_deref(), Some("msg_test"));
                assert!(!event.naming_thread);
            }
        }
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
        anthropic_exchange_with_headers(
            process_name,
            &[("x-claude-code-session-id", "session-1")],
            request_body,
        )
    }

    fn anthropic_exchange_with_headers(
        process_name: &str,
        headers: &[(&str, &str)],
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
        let mut request = Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("host", "api.anthropic.com")
            .header("content-type", "application/json");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let request = request
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
