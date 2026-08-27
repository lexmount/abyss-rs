//! Claude Web private conversation-completion parsing.
//!
//! This module understands the Claude Web wire dialect only. Harness identity
//! (Claude Desktop or another client) is resolved before protocol parsing.

use std::fmt;

use abyss_mitm::HttpExchange;
use http::Method;
use serde::Serialize;

use crate::protocol::model::{
    digest::sha256_hex,
    image::{ParsedImageAttachment, extract_anthropic_request_images},
    text::non_empty_trimmed,
    tool::ParsedToolEvent,
    usage::{TokenUsage, TokenUsageSource},
};

use super::super::messages::{
    best_usage, claude_web_file_uuids, estimated_visible_usage, event_types, extract_request_texts,
    extract_request_tool_events, extract_response_texts, extract_response_tool_events,
    first_message_id, first_model, first_stop_reason, flow_server_name, request_host,
    response_values, string_field, transport_name, turn_message_uuids,
};

/// Source used to derive the Claude Web session id.
#[derive(Debug, Clone, Copy, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ClaudeWebSessionIdSource {
    /// Conversation id parsed from the private Claude Web path.
    ConversationPath,
}

impl fmt::Display for ClaudeWebSessionIdSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConversationPath => formatter.write_str("conversation_path"),
        }
    }
}

/// Wire-level values extracted from one Claude Web completion interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedClaudeWebExchange {
    /// Normalized request host.
    pub host: String,
    /// Claude Web conversation-completion path.
    pub path: String,
    /// HTTP method.
    pub method: String,
    /// Transport observed by `abyss-mitm`: `http`, `https`, or `unknown`.
    pub transport: &'static str,
    /// Conversation id used to group turns.
    pub session_id: String,
    /// Source used to derive `session_id`.
    pub session_id_source: ClaudeWebSessionIdSource,
    /// Hash of method, host, path, and request body for event correlation.
    pub request_hash: String,
    /// User-visible prompt fragments extracted from the request body.
    pub request_texts: Vec<String>,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// File UUIDs referencing images uploaded through the Claude Web file API.
    pub request_file_uuids: Vec<String>,
    /// Stable logical turn id supplied by Claude Web.
    pub protocol_turn_id: Option<String>,
    /// Tool results submitted on the request side of this provider call.
    pub request_tool_events: Vec<ParsedToolEvent>,
    /// Tool calls and results streamed on the response side.
    pub response_tool_events: Vec<ParsedToolEvent>,
    /// Assistant response fragments extracted from SSE response data.
    pub response_texts: Vec<String>,
    /// Provider token counters or a visible-content estimate when absent.
    pub usage: TokenUsage,
    /// Whether token counters were provider-reported or estimated.
    pub usage_source: TokenUsageSource,
    /// Anthropic message id when present.
    pub message_id: Option<String>,
    /// Provider model name.
    pub model: Option<String>,
    /// Human message UUID supplied by the request.
    pub human_message_uuid: Option<String>,
    /// Assistant message UUID supplied by the request.
    pub assistant_message_uuid: Option<String>,
    /// Response stop reason when the SSE stream exposes one.
    pub stop_reason: Option<String>,
    /// Provider event type strings found in response JSON/SSE payloads.
    pub event_types: Vec<String>,
}

/// Parses one Claude Web private conversation-completion exchange.
#[must_use]
pub fn parse_claude_web_exchange(exchange: &HttpExchange) -> Option<ParsedClaudeWebExchange> {
    if exchange.request.method() != Method::POST {
        return None;
    }

    let host = request_host(exchange.request.headers(), exchange.request.uri())
        .or_else(|| flow_server_name(&exchange.flow))?;
    let path = exchange.request.uri().path();
    let conversation_id = completion_conversation_id(path)?;
    let request_json = exchange.request.body().json()?;
    let request_texts = extract_request_texts(request_json, false);
    let request_images = extract_anthropic_request_images(request_json);
    let request_file_uuids = claude_web_file_uuids(request_json);
    let request_tool_events = extract_request_tool_events(request_json);
    if request_texts.is_empty()
        && request_images.is_empty()
        && request_file_uuids.is_empty()
        && request_tool_events.is_empty()
    {
        return None;
    }

    let response_values = response_values(exchange.response.headers(), exchange.response.body());
    let response_texts = extract_response_texts(&response_values);
    let response_tool_events = extract_response_tool_events(&response_values);
    let (usage, usage_source) = best_usage(&response_values)
        .or_else(|| best_usage(std::slice::from_ref(request_json)))
        .map_or_else(
            || {
                let usage = estimated_visible_usage(
                    &request_texts,
                    &request_tool_events,
                    &response_texts,
                    &response_tool_events,
                );
                let source = if usage.is_empty() {
                    TokenUsageSource::Absent
                } else {
                    TokenUsageSource::EstimatedVisibleContent
                };
                (usage, source)
            },
            |usage| (usage, TokenUsageSource::ProviderReported),
        );
    let turn_message_uuids = turn_message_uuids(request_json);
    let protocol_turn_id = turn_message_uuids
        .assistant
        .clone()
        .or_else(|| turn_message_uuids.human.clone());
    let request_hash = sha256_hex(&format!(
        "{}\0{}\0{}\0{}",
        exchange.request.method(),
        host,
        path,
        String::from_utf8_lossy(exchange.request.body().bytes())
    ));

    Some(ParsedClaudeWebExchange {
        host,
        path: path.to_owned(),
        method: exchange.request.method().to_string(),
        transport: transport_name(&exchange.flow.protocol),
        session_id: conversation_id.to_owned(),
        session_id_source: ClaudeWebSessionIdSource::ConversationPath,
        request_hash,
        request_texts,
        request_images,
        request_file_uuids,
        protocol_turn_id,
        request_tool_events,
        response_tool_events,
        response_texts,
        usage,
        usage_source,
        message_id: first_message_id(&response_values)
            .or_else(|| turn_message_uuids.assistant.clone()),
        model: first_model(&response_values)
            .or_else(|| string_field(request_json, "model").map(str::to_owned)),
        human_message_uuid: turn_message_uuids.human,
        assistant_message_uuid: turn_message_uuids.assistant,
        stop_reason: first_stop_reason(&response_values),
        event_types: response_values.iter().flat_map(event_types).collect(),
    })
}

fn completion_conversation_id(path: &str) -> Option<&str> {
    let mut segments = path.split('/');
    if !segments.next()?.is_empty()
        || segments.next()? != "api"
        || segments.next()? != "organizations"
    {
        return None;
    }
    let _organization_id = non_empty_trimmed(segments.next()?)?;
    if segments.next()? != "chat_conversations" {
        return None;
    }
    let conversation_id = non_empty_trimmed(segments.next()?)?;
    if segments.next()? != "completion" || segments.next().is_some() {
        return None;
    }
    Some(conversation_id)
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
    };
    use http::{Request, Response};
    use serde_json::json;

    use crate::protocol::model::usage::TokenUsageSource;

    use super::parse_claude_web_exchange;

    #[test]
    fn parses_conversation_completion_without_harness_metadata() {
        let exchange = completion_exchange(
            "POST",
            &json!({
                "model": "claude-test",
                "prompt": "hello desktop",
                "files": ["file-1"],
                "turn_message_uuids": {
                    "human_message_uuid": "human-1",
                    "assistant_message_uuid": "assistant-1"
                }
            }),
            concat!(
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":",
                "{\"type\":\"text_delta\",\"text\":\"hello user\"}}\n\n"
            ),
        );

        let parsed = parse_claude_web_exchange(&exchange).expect("Claude Web exchange");

        assert_eq!(parsed.session_id, "conversation-1");
        assert_eq!(parsed.request_texts, vec!["hello desktop"]);
        assert_eq!(parsed.response_texts, vec!["hello user"]);
        assert_eq!(parsed.request_file_uuids, vec!["file-1"]);
        assert_eq!(parsed.protocol_turn_id.as_deref(), Some("assistant-1"));
        assert!(matches!(
            parsed.usage_source,
            TokenUsageSource::EstimatedVisibleContent
        ));
    }

    #[test]
    fn uses_provider_reported_usage_when_available() {
        let exchange = completion_exchange(
            "POST",
            &json!({
                "prompt": "hello",
                "turn_message_uuids": {"human_message_uuid": "human-1"}
            }),
            concat!(
                "data: {\"type\":\"message_delta\",\"usage\":",
                "{\"input_tokens\":2,\"output_tokens\":3}}\n\n"
            ),
        );

        let parsed = parse_claude_web_exchange(&exchange).expect("Claude Web exchange");

        assert_eq!(parsed.usage.total_tokens, 5);
        assert!(matches!(
            parsed.usage_source,
            TokenUsageSource::ProviderReported
        ));
    }

    #[test]
    fn rejects_non_post_and_non_completion_routes() {
        assert!(
            parse_claude_web_exchange(
                &completion_exchange("GET", &json!({"prompt": "hello"}), "",)
            )
            .is_none()
        );

        let mut exchange = completion_exchange("POST", &json!({"prompt": "hello"}), "");
        *exchange.request.uri_mut() = "/api/organizations/org/conversations".parse().unwrap();
        assert!(parse_claude_web_exchange(&exchange).is_none());
    }

    fn completion_exchange(
        method: &str,
        request_body: &serde_json::Value,
        response_sse: &str,
    ) -> HttpExchange {
        HttpExchange::new(
            FlowContext::new(
                SocketAddr::from(([127, 0, 0, 1], 50_000)),
                SocketAddr::from(([127, 0, 0, 1], 18_090)),
                OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                TransparentProtocol::TlsHttp {
                    server_name: "claude.ai".to_owned(),
                },
            ),
            Request::builder()
                .method(method)
                .uri("/api/organizations/org-1/chat_conversations/conversation-1/completion")
                .header("host", "claude.ai")
                .header("content-type", "application/json")
                .body(CapturedBody::from_bytes(
                    serde_json::to_vec(request_body).unwrap().into(),
                ))
                .unwrap(),
            Response::builder()
                .header("content-type", "text/event-stream")
                .body(CapturedBody::from_bytes(
                    response_sse.as_bytes().to_vec().into(),
                ))
                .unwrap(),
        )
    }
}
