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

        match protocol {
            LlmProtocol::OpenAi(OpenAiProtocol::Responses | OpenAiProtocol::ChatCompletions) => {
                let Some(parsed) = parse_openai_exchange(exchange) else {
                    return Vec::new();
                };
                self.normalize(&parsed, &content, &detection, &provider)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::Messages) => {
                let Some(parsed) = parse_anthropic_messages_exchange(exchange) else {
                    return Vec::new();
                };
                self.normalize(&parsed, &content, &detection, &provider)
            }
            LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(
                ClaudeWebProtocol::ConversationCompletion,
            )) => {
                let Some(mut parsed) = parse_claude_web_exchange(exchange) else {
                    return Vec::new();
                };
                self.claude_web_context
                    .attach_referenced_images(&mut parsed);
                self.normalize(&parsed, &content, &detection, &provider)
            }
        }
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
        let parsed = parse_openai_websocket_message(message);
        let Some(parsed) = self.openai_websocket.push(&message.flow.flow_id, parsed) else {
            return Vec::new();
        };
        let provider = ProviderResolver::resolve(&websocket_host(message), protocol);
        let content = policy
            .harness_usage
            .config
            .content_for_harness(detection.harness_id.as_str());
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
