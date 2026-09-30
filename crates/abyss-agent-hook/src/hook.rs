//! Single coordinator for Harness detection, protocol parsing, correlation, and delivery.

use std::sync::Arc;

use abyss_mitm::{FlowContext, HookError, HookFuture, HttpExchange, MitmHook, WebSocketMessage};
use abyss_plugin_protocol::event::LlmProvider;
use http::{HeaderMap, header::HOST};

use crate::{
    config::{HarnessUsageHookConfig, HooksRuntimeConfig},
    correlation::CorrelationRegistry,
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
    correlation: CorrelationRegistry,
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
            correlation: CorrelationRegistry::default(),
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

        let mut events = match protocol {
            LlmProtocol::OpenAi(OpenAiProtocol::Responses | OpenAiProtocol::ChatCompletions) => {
                let Some(parsed) = parse_openai_exchange(exchange) else {
                    return Vec::new();
                };
                self.normalize(&parsed, &content, &detection, &provider)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::Messages) => {
                let Some(parsed) = parse_anthropic_messages_exchange(exchange) else {
                    return self.unparsed_http(exchange, &content, &detection, &provider);
                };
                self.normalize(&parsed, &content, &detection, &provider)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(
                ClaudeWebProtocol::ConversationCompletion,
            )) => {
                let Some(mut parsed) = parse_claude_web_exchange(exchange) else {
                    return self.unparsed_http(exchange, &content, &detection, &provider);
                };
                self.claude_web_context
                    .attach_referenced_images(&mut parsed);
                self.normalize(&parsed, &content, &detection, &provider)
            }
        };
        if crate::raw_body::enabled(&content) {
            for event in &mut events {
                crate::raw_body::attach(
                    event,
                    if event.event_type == "request" {
                        crate::raw_body::http(exchange.request.body(), exchange.request.headers())
                    } else {
                        crate::raw_body::http(exchange.response.body(), exchange.response.headers())
                    },
                );
            }
        }
        events
    }

    fn unparsed_http(
        &self,
        exchange: &HttpExchange,
        content: &crate::config::HarnessUsageContentConfig,
        detection: &HarnessDetection,
        provider: &LlmProvider,
    ) -> Vec<NormalizedUsageEvent> {
        if !crate::raw_body::enabled(content) {
            return Vec::new();
        }
        // The generic exchange adapter supplies identity even for malformed or
        // binary payloads. Raw retention must not depend on a successful parser.
        let Some(parsed) = parse_openai_exchange(exchange) else {
            return Vec::new();
        };
        let mut events = self.normalize(&parsed, content, detection, provider);
        for event in &mut events {
            crate::raw_body::attach(
                event,
                if event.event_type == "request" {
                    crate::raw_body::http(exchange.request.body(), exchange.request.headers())
                } else {
                    crate::raw_body::http(exchange.response.body(), exchange.response.headers())
                },
            );
        }
        events
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
        let correlation =
            self.correlation
                .assign(detection, parsed.session_id(), parsed.protocol_turn_id());
        normalize_exchange(
            &self.config,
            parsed,
            content,
            detection,
            provider,
            &correlation,
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
        let parsed = parse_openai_websocket_message(message);
        let raw = crate::raw_body::enabled(&content).then_some(message);
        let Some(parsed) = self
            .openai_websocket
            .push(&message.flow.flow_id, parsed, raw)
        else {
            return Vec::new();
        };
        let provider = ProviderResolver::resolve(&websocket_host(message), protocol);
        let content = policy
            .harness_usage
            .config
            .content_for_harness(detection.harness_id.as_str());
        let mut events = self.normalize(&parsed, &content, &detection, &provider);
        if crate::raw_body::enabled(&content) {
            for event in &mut events {
                crate::raw_body::attach(
                    event,
                    abyss_plugin_protocol::event::RawBody {
                        transport: abyss_plugin_protocol::event::RawTransport::Websocket,
                        parts: if event.event_type == "request" {
                            parsed.raw_request.clone()
                        } else {
                            parsed.raw_response.clone()
                        },
                    },
                );
            }
        }
        events
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
    use abyss_plugin_protocol::event::AgentEvent;
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
    async fn archives_exact_http_bodies_before_parsing_and_preserves_failed_responses() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use sha2::{Digest as _, Sha256};
        let request = b" {\"model\":\"gpt-test\",\"input\":[{\"role\":\"developer\",\"content\":\"instructions\"},{\"role\":\"user\",\"content\":\"continue\"},{\"role\":\"user\",\"content\":\"continue\"}],\"tools\":[{\"name\":\"exec\",\"schema\":{\"unknown\":42}}],\"extra\": [1,1]} \n";
        let response = b"event: response.output_text.delta\r\ndata: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\r\n\r\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"r1\",\"unknown\":true}}\r\n\r\ndata: [DONE]\r\n\r\n";
        for response in [
            response.as_slice(),
            b"{\"error\":{\"code\":\"overloaded\",\"details\": [1,2]}}\n",
            b"\xff\0\x80",
        ] {
            let sink = Arc::new(RecordingSink::default());
            let hook = hook(Arc::clone(&sink));
            let mut exchange = openai_exchange("acme-agent");
            *exchange.request.body_mut() = CapturedBody::from_bytes(request.to_vec().into());
            *exchange.response.body_mut() = CapturedBody::from_bytes(response.to_vec().into());
            hook.on_http_exchange(&exchange).await.unwrap();
            let events = sink.events.lock().unwrap();
            assert_eq!(events.len(), 2);
            for (event, expected) in events.iter().zip([request.as_slice(), response]) {
                let part = &event.raw_body.as_ref().unwrap().parts[0];
                let bytes = STANDARD.decode(&part.content_base64).unwrap();
                assert_eq!(bytes, expected);
                assert_eq!(part.byte_size, u64::try_from(expected.len()).unwrap());
                assert_eq!(part.sha256, hex::encode(Sha256::digest(expected)));
                assert!(!part.truncated);
            }
        }
    }

    #[tokio::test]
    async fn separate_observations_keep_distinct_archives_even_with_identical_text() {
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let exchange = openai_exchange("acme-agent");
        hook.on_http_exchange(&exchange).await.unwrap();
        hook.on_http_exchange(&exchange).await.unwrap();
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 4);
        assert_ne!(events[0].event_id, events[2].event_id);
        assert_ne!(events[1].event_id, events[3].event_id);
        assert_eq!(
            serde_json::to_value(&events[0].raw_body).unwrap(),
            serde_json::to_value(&events[2].raw_body).unwrap()
        );
        drop(events);
    }

    #[tokio::test]
    async fn websocket_archives_duplicate_and_unparsed_messages_in_sequence() {
        use abyss_mitm::{WebSocketDirection, WebSocketMessage};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let exchange = openai_exchange("acme-agent");
        let (parts, _) = exchange.request.into_parts();
        let upgrade = Request::from_parts(parts, ());
        let request = " {\"type\":\"response.create\",\"response\":{\"model\":\"test\",\"input\":[{\"role\":\"user\",\"content\":\"hello\"}]}}\n";
        let unknown = " {\"type\":\"unknown\",\"extra\": [1,1]} ";
        let terminal = "{\"type\":\"response.failed\",\"response\":{\"id\":\"failed-1\",\"error\":{\"message\":\"failure\"}}}";
        for (sequence, direction, body) in [
            (1, WebSocketDirection::ClientToServer, request),
            (2, WebSocketDirection::ServerToClient, unknown),
            (3, WebSocketDirection::ServerToClient, unknown),
            (4, WebSocketDirection::ServerToClient, terminal),
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
        for (event, expected) in events.iter().zip([
            vec![(1, request)],
            vec![(2, unknown), (3, unknown), (4, terminal)],
        ]) {
            let parts = &event.raw_body.as_ref().unwrap().parts;
            assert_eq!(parts.len(), expected.len());
            for (part, (sequence, body)) in parts.iter().zip(expected) {
                assert_eq!(part.sequence, Some(sequence));
                assert_eq!(
                    STANDARD.decode(&part.content_base64).unwrap(),
                    body.as_bytes()
                );
            }
        }
    }

    #[tokio::test]
    async fn archives_malformed_anthropic_body_without_requiring_a_successful_parser() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        let sink = Arc::new(RecordingSink::default());
        let hook = hook(Arc::clone(&sink));
        let mut exchange = anthropic_exchange("acme-agent");
        *exchange.request.body_mut() =
            CapturedBody::from_truncated_bytes(b"{\"messages\": [".to_vec().into());
        hook.on_http_exchange(&exchange).await.unwrap();
        let events = sink.events.lock().unwrap();
        assert_eq!(events.len(), 2);
        let part = &events[0].raw_body.as_ref().unwrap().parts[0];
        assert!(part.truncated);
        assert_eq!(
            STANDARD.decode(&part.content_base64).unwrap(),
            exchange.request.body().bytes()
        );
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
            .body(CapturedBody::from_bytes(
                serde_json::to_vec(&serde_json::json!({
                    "model": "claude-test",
                    "messages": [{"role": "user", "content": "hello"}]
                }))
                .unwrap()
                .into(),
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
