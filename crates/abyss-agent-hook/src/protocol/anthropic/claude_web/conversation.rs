//! Claude Web private conversation-completion parsing.
//!
//! This module understands the Claude Web wire dialect only. Harness identity
//! (Claude Desktop or another client) is resolved before protocol parsing.

use abyss_mitm::HttpExchange;
use http::Method;

use super::metadata::{assistant_message_uuid, claude_web_file_uuids};
use crate::protocol::{
    anthropic::shared::{
        conversation::{AnthropicRequest, AnthropicResponse},
        images::extract_anthropic_request_images,
        metadata::first_model,
        usage::{best_usage, estimated_visible_usage},
    },
    model::{image::ParsedImageAttachment, usage::TokenUsage},
    shared::{
        digest::sha256_hex,
        http::{flow_server_name, request_host},
        json::string_field,
        sse::ResponseDocuments,
        text::non_empty_trimmed,
    },
};

/// Wire-level values extracted from one Claude Web completion interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedClaudeWebExchange {
    /// Conversation id used to group turns.
    pub session_id: String,
    /// Hash of method, host, path, and request body for event correlation.
    pub request_hash: String,
    /// Structured request messages decoded from the request body.
    pub request_conversation: abyss_plugin_protocol::event::Conversation,
    /// Structured response messages assembled from the response documents.
    pub response_conversation: abyss_plugin_protocol::event::Conversation,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// File UUIDs referencing images uploaded through the Claude Web file API.
    pub request_file_uuids: Vec<String>,
    /// Provider token counters or a visible-content estimate when absent.
    pub usage: TokenUsage,
    /// Anthropic message id when present.
    pub message_id: Option<String>,
    /// Provider model name.
    pub model: Option<String>,
    /// Assistant message UUID supplied by the request.
    pub assistant_message_uuid: Option<String>,
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
    let request_conversation =
        AnthropicRequest::parse(request_json, exchange.request.body().truncated()).conversation();
    let request_images = extract_anthropic_request_images(request_json);
    let request_file_uuids = claude_web_file_uuids(request_json);
    if request_conversation.entries.is_empty()
        && request_images.is_empty()
        && request_file_uuids.is_empty()
    {
        return None;
    }

    let response_documents = ResponseDocuments::decode(exchange.response.body());
    let response_values = response_documents.values;
    let response = AnthropicResponse::assemble(&response_values, response_documents.incomplete);
    let response_conversation = response.conversation();
    let usage = best_usage(&response_values)
        .or_else(|| best_usage(std::slice::from_ref(request_json)))
        .unwrap_or_else(|| estimated_visible_usage(&request_conversation, &response_conversation));
    let assistant_message_uuid = assistant_message_uuid(request_json);
    let request_hash = sha256_hex(&format!(
        "{}\0{}\0{}\0{}",
        exchange.request.method(),
        host,
        path,
        String::from_utf8_lossy(exchange.request.body().bytes())
    ));

    Some(ParsedClaudeWebExchange {
        session_id: conversation_id.to_owned(),
        request_hash,
        request_conversation,
        response_conversation,
        request_images,
        request_file_uuids,
        usage,
        message_id: response
            .id()
            .map(str::to_owned)
            .or_else(|| assistant_message_uuid.clone()),
        model: first_model(&response_values)
            .or_else(|| string_field(request_json, "model").map(str::to_owned)),
        assistant_message_uuid,
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
    use abyss_plugin_protocol::event::EntryRole;
    use http::{Request, Response};
    use serde_json::json;

    use crate::protocol::model::conversation::role_texts;

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
        assert_eq!(
            role_texts(&parsed.request_conversation),
            [(EntryRole::User, "hello desktop")]
        );
        assert_eq!(
            role_texts(&parsed.response_conversation),
            [(EntryRole::Assistant, "hello user")]
        );
        assert_eq!(parsed.request_file_uuids, vec!["file-1"]);
        // One token per four bytes of trimmed entry text.
        assert_eq!(parsed.usage.input_tokens, 4);
        assert_eq!(parsed.usage.output_tokens, 3);
    }

    #[test]
    fn estimates_usage_from_every_entry_and_tool_names() {
        let exchange = completion_exchange(
            "POST",
            &json!({"prompt": "hi"}),
            concat!(
                "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
                "{\"type\":\"thinking\",\"thinking\":\"plan\"}}\n\n",
                "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":",
                "{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"web\",\"input\":{\"q\":1}}}\n\n"
            ),
        );

        let parsed = parse_claude_web_exchange(&exchange).expect("Claude Web exchange");

        assert_eq!(parsed.usage.input_tokens, 1);
        // `plan` (4) + `web` (3) + `{"q":1}` (7) bytes.
        assert_eq!(parsed.usage.output_tokens, 4);
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
