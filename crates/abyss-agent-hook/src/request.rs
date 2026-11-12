//! Request-only facade over the same recognition, extraction and normalization as observation.

#[cfg(test)]
mod tests;

mod auth;
mod edit;
mod endpoint;
pub use edit::{RequestActionError, RequestActions};

use std::sync::Arc;

use abyss_mitm::{RequestTransport, RequestView, TransparentProtocol};
use abyss_plugin_protocol::{
    event::ImageAttachment,
    inspection::{
        AgentRequestContext, AgentRequestProjection, DecodedContent, RequestHarness,
        RequestMessageType, RequestParsingStatus, RequestSourceProcess,
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    HarnessUsageConfig, HarnessUsageContentConfig,
    event::normalizer::{AgentEventConversionError, normalized_image_attachments},
    harness::{DeclarationSource, HarnessRegistry},
    protocol::{
        AnthropicProtocol, LlmProtocol, OpenAiProtocol, ProtocolDetector,
        model::request::{ParsedAgentRequest, RequestContent},
        request::RequestParser,
        shared::http::{flow_server_name, request_host},
    },
    provider::ProviderResolver,
};

/// Stateless request projection; never synthesizes a response or usage event.
pub struct AgentRequestParser;

impl AgentRequestParser {
    /// Parses request content once so inspection and observation can share it.
    #[must_use]
    pub fn prepare(request: &RequestView<'_>) -> ParsedAgentRequest {
        let json = request.body.json();
        let payload = match request.transport {
            RequestTransport::Http => json,
            _ => json.map(|value| value.get("response").unwrap_or(value)),
        };
        let protocol = ProtocolDetector::detect_request(request.head.uri().path(), payload);
        ParsedAgentRequest {
            projection: protocol.map(|protocol| {
                (
                    protocol,
                    Arc::new(RequestParser::parse(
                        protocol,
                        payload,
                        request.body.truncated(),
                    )),
                )
            }),
        }
    }

    /// Builds a complete inspection context independently of audit content policy.
    #[must_use]
    pub fn parse(
        request: &RequestView<'_>,
        config: &HarnessUsageConfig,
        request_id: String,
    ) -> AgentRequestContext {
        let parsed = Self::prepare(request);
        Self::parse_prepared(&parsed, request, config, request_id)
    }

    /// Projects an already parsed request without repeating protocol extraction.
    #[must_use]
    pub fn parse_prepared(
        parsed: &ParsedAgentRequest,
        request: &RequestView<'_>,
        config: &HarnessUsageConfig,
        request_id: String,
    ) -> AgentRequestContext {
        let json = request.body.json();
        let (sequence, message_type) = match request.transport {
            RequestTransport::Http => (1, None),
            RequestTransport::WebSocketText { sequence } => {
                (sequence, Some(RequestMessageType::Text))
            }
            RequestTransport::WebSocketBinary { sequence } => {
                (sequence, Some(RequestMessageType::Binary))
            }
        };
        let websocket = message_type.is_some();
        let payload = if websocket {
            json.map(|value| value.get("response").unwrap_or(value))
        } else {
            json
        };
        let authority = request_host(request.head.headers(), request.head.uri())
            .or_else(|| flow_server_name(request.flow));
        let (agent, parsing_status) = match (parsed.projection.as_ref(), payload) {
            (None, _) => (None, RequestParsingStatus::UnknownProtocol),
            (Some(_), None) => (None, RequestParsingStatus::InvalidPayload),
            (Some((protocol, content)), Some(_)) => Self::project(
                *protocol,
                content,
                authority.as_deref().unwrap_or("unknown"),
            )
            .map_or((None, RequestParsingStatus::InvalidPayload), |agent| {
                (Some(agent), RequestParsingStatus::Parsed)
            }),
        };
        let harness = Self::harness(request, config, payload);
        let mut context = AgentRequestContext {
            flow_id: request.flow.flow_id.to_string(),
            request_id,
            ingress: request.flow.ingress.source_label().to_owned(),
            source_process: request.flow.source_process.as_ref().map(|source| {
                RequestSourceProcess {
                    pid: source.pid,
                    pid_version: source.pid_version,
                    name: source.name.clone(),
                    executable_path: source.executable_path.clone(),
                    application_id: source.application_id.clone(),
                    entry_point: source.entry_point.clone(),
                    working_directory: source.working_directory.clone(),
                }
            }),
            destination: request.flow.original_destination.to_string(),
            destination_host: request.flow.destination_host.clone(),
            server_name: match &request.flow.protocol {
                TransparentProtocol::TlsHttp { server_name } => Some(server_name.clone()),
                _ => None,
            },
            authority,
            proxy_endpoint: request.flow.ingress.proxy_endpoint().map(str::to_owned),
            method: request.head.method().to_string(),
            path: request
                .head
                .uri()
                .path_and_query()
                .map_or_else(|| "/".to_owned(), ToString::to_string),
            websocket,
            sequence,
            message_type,
            headers: Self::headers(request),
            body: std::str::from_utf8(request.body.bytes()).map_or_else(
                |_| DecodedContent::Base64(STANDARD.encode(request.body.bytes())),
                |text| DecodedContent::Utf8(text.to_owned()),
            ),
            json: json.cloned(),
            parsing_status,
            harness,
            auth_token: None,
            auth_token_writable: false,
            model_writable: false,
            provider: None,
            provider_writable: false,
            agent,
        };
        RequestActions::new(request).annotate(request, &mut context);
        context
    }

    fn headers(request: &RequestView<'_>) -> Vec<(String, String)> {
        request
            .head
            .headers()
            .iter()
            .filter(|(name, _)| !abyss_mitm::is_sensitive_header(name))
            .map(|(name, value)| {
                (
                    name.to_string(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect()
    }

    fn harness(
        request: &RequestView<'_>,
        config: &HarnessUsageConfig,
        payload: Option<&serde_json::Value>,
    ) -> Option<RequestHarness> {
        HarnessRegistry::recognize(
            request.flow,
            request.head.headers(),
            request.head.uri().path(),
            config,
            false,
        )
        .map(|detection| {
            let declaration = HarnessRegistry::declare(
                &detection.harness_id,
                &DeclarationSource {
                    headers: matches!(request.transport, RequestTransport::Http)
                        .then_some(request.head.headers()),
                    connection_headers: (!matches!(request.transport, RequestTransport::Http))
                        .then_some(request.head.headers()),
                    client_metadata: payload.and_then(|value| value.get("client_metadata")),
                },
            );
            RequestHarness {
                id: detection.harness_id.as_str().to_owned(),
                version: detection.version.clone(),
                turn_id: declaration.turn_id,
                subagent_id: declaration.subagent_id,
                parent_subagent_id: declaration.parent_subagent_id,
                purpose: declaration.purpose,
            }
        })
    }

    fn project(
        protocol: LlmProtocol,
        request: &RequestContent,
        host: &str,
    ) -> Result<AgentRequestProjection, AgentEventConversionError> {
        let attachments = normalized_image_attachments(
            &request.images,
            &HarnessUsageContentConfig {
                images: true,
                ..HarnessUsageContentConfig::default()
            },
        )
        .into_iter()
        .map(ImageAttachment::try_from)
        .collect::<Result<_, _>>()?;
        Ok(AgentRequestProjection {
            protocol: match protocol {
                LlmProtocol::OpenAi(OpenAiProtocol::Responses) => "openai_responses",
                LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions) => "openai_chat_completions",
                LlmProtocol::Anthropic(AnthropicProtocol::Messages) => "anthropic_messages",
                LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(_)) => "claude_web",
            }
            .to_owned(),
            provider: ProviderResolver::resolve(host, protocol),
            model: request.metadata.model.clone(),
            conversation: request.conversation.clone(),
            attachments,
            tools: request.metadata.tool_definitions.clone(),
            previous_response_id: request.metadata.previous_response_id.clone(),
        })
    }
}
