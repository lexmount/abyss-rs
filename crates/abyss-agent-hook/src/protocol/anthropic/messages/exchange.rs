//! Anthropic Messages HTTP exchange parsing, independent of Harness identity.

use abyss_mitm::HttpExchange;
use http::Method;

use super::{model::ParsedAnthropicMessagesExchange, session::anthropic_session_id};
use crate::protocol::{
    anthropic::shared::{
        conversation::{AnthropicRequest, AnthropicResponse},
        images::extract_anthropic_request_images,
        metadata::first_model,
        usage::best_usage,
    },
    shared::{
        digest::sha256_hex,
        http::{flow_server_name, header, request_host, transport_name},
        json::{event_types, string_field},
        sse::ResponseDocuments,
    },
};

/// Parses an Anthropic Messages exchange without Harness assumptions.
#[must_use]
pub fn parse_anthropic_messages_exchange(
    exchange: &HttpExchange,
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

    let request_conversation =
        AnthropicRequest::parse(request_json, exchange.request.body().truncated()).conversation();
    let request_images = extract_anthropic_request_images(request_json);
    // Bootstrap, registry, and telemetry calls are useful transport evidence but
    // not dialogue turns. Upload only exchanges whose request carries content:
    // a conversation entry or an image.
    if request_conversation.entries.is_empty() && request_images.is_empty() {
        log_parse_skip(exchange, Some(&host), path, "no_dialogue_request_text");
        return None;
    }

    let response_documents = ResponseDocuments::decode(exchange.response.body());
    let response_values = response_documents.values;
    let response = AnthropicResponse::assemble(&response_values, response_documents.incomplete);
    let usage = best_usage(&response_values)
        .or_else(|| best_usage(std::slice::from_ref(request_json)))
        .unwrap_or_default();
    let message_id = response.id().map(str::to_owned);
    let model = first_model(&response_values)
        .or_else(|| string_field(request_json, "model").map(str::to_owned));
    let request_hash = sha256_hex(&format!(
        "{}\0{}\0{}\0{}",
        exchange.request.method(),
        host,
        path,
        String::from_utf8_lossy(exchange.request.body().bytes())
    ));
    let session = anthropic_session_id(headers, request_json, &host);
    let previous_response_id = request_json
        .get("thread")
        .filter(|thread| string_field(thread, "type") == Some("continue"))
        .and_then(|thread| string_field(thread, "previous_message_id"))
        .map(str::to_owned);

    Some(ParsedAnthropicMessagesExchange {
        host,
        path: path.to_owned(),
        method: exchange.request.method().to_string(),
        transport: transport_name(&exchange.flow.protocol),
        session_id: session.id,
        session_id_source: session.source,
        request_hash,
        request_conversation,
        response_conversation: response.conversation(),
        request_images,
        previous_response_id,
        usage,
        message_id,
        model,
        anthropic_version: header(headers, "anthropic-version").map(str::to_owned),
        event_types: response_values.iter().flat_map(event_types).collect(),
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
