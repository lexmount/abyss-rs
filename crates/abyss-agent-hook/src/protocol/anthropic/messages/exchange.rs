//! Anthropic Messages HTTP exchange parsing, independent of Harness identity.

use abyss_mitm::HttpExchange;
use http::Method;

use super::{
    model::ParsedAnthropicMessagesExchange, parser::MessagesParser, session::anthropic_session_id,
};
use crate::protocol::{
    model::{request::RequestContent, response::ResponseContent},
    parser::parse_http_exchange,
    shared::{
        digest::sha256_hex,
        http::{flow_server_name, request_host},
    },
};

/// Parses an Anthropic Messages exchange without Harness assumptions.
#[must_use]
pub fn parse_anthropic_messages_exchange(
    exchange: &HttpExchange,
) -> Option<ParsedAnthropicMessagesExchange> {
    parse_http_exchange::<MessagesParser, _, _>(exchange, assemble_exchange)
}

fn assemble_exchange(
    exchange: &HttpExchange,
    request: RequestContent,
    response: ResponseContent,
) -> Option<ParsedAnthropicMessagesExchange> {
    let Some(host) = request_host(exchange.request.headers(), exchange.request.uri())
        .or_else(|| flow_server_name(&exchange.flow))
    else {
        log_parse_skip(exchange, None, "", "missing_host");
        return None;
    };

    let path = exchange.request.uri().path();
    let Some(request_json) = exchange.request.body().json() else {
        log_parse_skip(exchange, Some(&host), path, "request_body_not_json");
        return None;
    };
    let headers = exchange.request.headers();

    let request_conversation = request.conversation;
    let request_images = request.images;
    // Bootstrap, registry, and telemetry calls are useful transport evidence but
    // not dialogue turns. Upload only exchanges whose request carries content:
    // a conversation entry or an image.
    if request_conversation.entries.is_empty() && request_images.is_empty() {
        log_parse_skip(exchange, Some(&host), path, "no_dialogue_request_text");
        return None;
    }

    let usage = response.usage.or(request.usage).unwrap_or_default();
    let message_id = response.response_id;
    let model = response.model.or(request.metadata.model);
    let request_hash = sha256_hex(&format!(
        "{}\0{}\0{}\0{}",
        exchange.request.method(),
        host,
        path,
        String::from_utf8_lossy(exchange.request.body().bytes())
    ));
    let previous_response_id = request.metadata.previous_response_id;

    Some(ParsedAnthropicMessagesExchange {
        session_id: anthropic_session_id(headers, request_json, &host),
        request_hash,
        request_conversation,
        response_conversation: response.conversation,
        request_images,
        previous_response_id,
        usage,
        message_id,
        model,
    })
}

fn log_parse_skip(exchange: &HttpExchange, host: Option<&str>, path: &str, reason: &'static str) {
    // Empty-body GETs are common Claude bootstrap traffic. Logging every one at
    // info would bury the remaining parser-miss diagnostics.
    if reason == "request_body_not_json"
        && exchange.request.body().bytes().is_empty()
        && exchange.request.method() != Method::POST
    {
        return;
    }

    // Keep parser-miss diagnostics metadata-only. Prompt and response bodies are
    // controlled by usage content policy and must not leak through logs.
    tracing::info!(
        host = ?host,
        method = %exchange.request.method(),
        target_path = path,
        request_body_bytes = exchange.request.body().bytes().len(),
        request_body_truncated = exchange.request.body().truncated(),
        response_status = %exchange.response.status(),
        response_body_bytes = exchange.response.body().bytes().len(),
        response_body_truncated = exchange.response.body().truncated(),
        reason,
        "Anthropic Messages parser skipped HTTP exchange"
    );
}
