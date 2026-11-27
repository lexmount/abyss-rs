//! Deterministic HTTP route and wire-schema protocol selection.

use abyss_mitm::{FlowContext, HttpExchange, WebSocketMessage};
use http::Request;

/// Supported wire protocols, grouped independently from Harness identity.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LlmProtocol {
    OpenAi(OpenAiProtocol),
    Anthropic(AnthropicProtocol),
}

/// OpenAI-compatible wire dialects.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum OpenAiProtocol {
    Responses,
    ChatCompletions,
    ChatGptConversation,
}

/// Anthropic-compatible public and private wire dialects.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum AnthropicProtocol {
    Messages,
    ClaudeWeb(ClaudeWebProtocol),
    ClaudeCodeSession,
}

/// Claude Web private protocol operations that carry model interactions.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ClaudeWebProtocol {
    ConversationCompletion,
}

/// Selects at most one protocol parser for a captured exchange.
pub struct ProtocolDetector;

impl ProtocolDetector {
    pub fn detect_http(exchange: &HttpExchange) -> Option<LlmProtocol> {
        Self::detect_request(
            &exchange.flow,
            &exchange.request,
            exchange.request.body().json(),
        )
    }

    pub fn detect_request<B>(
        flow: &FlowContext,
        request: &Request<B>,
        payload: Option<&serde_json::Value>,
    ) -> Option<LlmProtocol> {
        let path = request.uri().path();
        if super::openai::chatgpt::matches_request(flow, request) {
            return Some(LlmProtocol::OpenAi(OpenAiProtocol::ChatGptConversation));
        }
        if super::anthropic::claude_code_session::matches_request(flow, request) {
            return Some(LlmProtocol::Anthropic(AnthropicProtocol::ClaudeCodeSession));
        }
        if path.contains("/organizations/") && path.ends_with("/completion") {
            return Some(LlmProtocol::Anthropic(AnthropicProtocol::ClaudeWeb(
                ClaudeWebProtocol::ConversationCompletion,
            )));
        }
        if path.starts_with("/v1/responses")
            || path.starts_with("/backend-api/codex/responses")
            || path.ends_with("/responses")
        {
            return Some(LlmProtocol::OpenAi(OpenAiProtocol::Responses));
        }
        if path.starts_with("/v1/chat/completions") || path.ends_with("/chat/completions") {
            return Some(LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions));
        }
        if path.starts_with("/v1/messages") || path.ends_with("/messages") {
            return Some(LlmProtocol::Anthropic(AnthropicProtocol::Messages));
        }

        let request = payload?;
        if request.get("input").is_some() {
            return Some(LlmProtocol::OpenAi(OpenAiProtocol::Responses));
        }
        request
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .map(|_| LlmProtocol::Anthropic(AnthropicProtocol::Messages))
    }

    /// Selects the protocol carried by one upgraded WebSocket flow.
    pub fn detect_websocket(message: &WebSocketMessage) -> Option<LlmProtocol> {
        let path = message.upgrade_request.uri().path();
        (path.starts_with("/v1/responses")
            || path.starts_with("/backend-api/codex/responses")
            || path.ends_with("/responses"))
        .then_some(LlmProtocol::OpenAi(OpenAiProtocol::Responses))
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
    };
    use http::{Request, Response};

    use super::{AnthropicProtocol, LlmProtocol, ProtocolDetector};

    #[test]
    fn detection_does_not_require_harness_metadata() {
        let exchange = exchange("/v1/messages", br#"{"model":"claude","messages":[]}"#);

        assert!(matches!(
            ProtocolDetector::detect_http(&exchange),
            Some(LlmProtocol::Anthropic(AnthropicProtocol::Messages))
        ));
    }

    #[test]
    fn chatgpt_conversation_protocol_requires_no_desktop_source() {
        let mut exchange = exchange(
            "https://chatgpt.com/backend-api/f/conversation",
            br#"{"messages":[]}"#,
        );
        *exchange.request.method_mut() = http::Method::POST;
        assert_eq!(
            ProtocolDetector::detect_http(&exchange),
            Some(LlmProtocol::OpenAi(
                super::OpenAiProtocol::ChatGptConversation
            ))
        );
    }

    #[test]
    fn claude_code_session_route_takes_precedence_over_the_body() {
        for (host, protocol) in [
            (
                "claude.ai",
                LlmProtocol::Anthropic(AnthropicProtocol::ClaudeCodeSession),
            ),
            (
                "gateway.example",
                LlmProtocol::OpenAi(super::OpenAiProtocol::Responses),
            ),
        ] {
            let exchange = exchange(
                &format!("https://{host}/v1/code/sessions/cse_test/events/stream"),
                br#"{"input":[]}"#,
            );
            assert_eq!(ProtocolDetector::detect_http(&exchange), Some(protocol));
        }
    }

    #[test]
    fn compatible_chat_completions_route_keeps_the_openai_family() {
        let exchange = exchange(
            "/gateway/chat/completions",
            br#"{"model":"compatible","messages":[]}"#,
        );

        assert!(matches!(
            ProtocolDetector::detect_http(&exchange),
            Some(LlmProtocol::OpenAi(super::OpenAiProtocol::ChatCompletions))
        ));
    }

    fn exchange(path: &str, body: &[u8]) -> HttpExchange {
        HttpExchange::new(
            FlowContext::from_optional_addrs(
                None,
                None,
                OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                TransparentProtocol::PlainHttp,
                None,
            ),
            Request::builder()
                .uri(path)
                .header("host", "gateway.example")
                .body(CapturedBody::from_bytes(body.to_vec().into()))
                .unwrap(),
            Response::new(CapturedBody::from_bytes(Vec::new().into())),
        )
    }
}
