//! Anthropic Messages wire parsing.
//!
//! This module consumes decoded HTTP exchanges from `abyss-mitm` and recognizes
//! Anthropic Messages-style traffic. It extracts the request and response
//! conversations, message ids, model names, and token usage while keeping
//! provider-specific details out of the MITM protocol layer.

use std::fmt;

use abyss_mitm::{FlowContext, HttpExchange, TransparentProtocol};
use abyss_plugin_protocol::event::{Conversation, EntryRole};
use http::{HeaderMap, Method, header::HOST};
use serde::Serialize;
use serde_json::Value;

use crate::{
    protocol::anthropic::conversation::{AnthropicRequest, AnthropicResponse},
    protocol::model::digest::sha256_hex,
    protocol::model::image::{ParsedImageAttachment, extract_anthropic_request_images},
    protocol::model::text::{MAX_PARSE_DEPTH, json_to_text, non_empty_trimmed},
    protocol::model::usage::TokenUsage,
    protocol::sse::ResponseDocuments,
};

/// Source used to derive the protocol session identity.
#[derive(Debug, Clone, Copy, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AnthropicSessionIdSource {
    /// Claude/Anthropic supplied an explicit session or thread id.
    Provider,
    /// No actual session identity was available; events are retained in a host bucket.
    Unattributed,
}

impl fmt::Display for AnthropicSessionIdSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider => formatter.write_str("provider"),
            Self::Unattributed => formatter.write_str("unattributed"),
        }
    }
}

/// Wire-level values extracted from one Anthropic Messages interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedAnthropicMessagesExchange {
    /// Normalized request host.
    pub host: String,
    /// Request path used to distinguish Anthropic API families.
    pub path: String,
    /// HTTP method.
    pub method: String,
    /// Transport observed by `abyss-mitm`: `http`, `https`, or `unknown`.
    pub transport: &'static str,
    /// Session/thread id used to group turns.
    pub session_id: String,
    /// Source used to derive `session_id`.
    pub session_id_source: AnthropicSessionIdSource,
    /// Hash of method, host, path, and request body for event correlation.
    pub request_hash: String,
    /// Structured request messages decoded from the request body.
    pub request_conversation: Conversation,
    /// Structured response messages assembled from the response documents.
    pub response_conversation: Conversation,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// The response this request continues after: `previous_message_id` of a
    /// `thread` `continue`.
    pub previous_response_id: Option<String>,
    /// Best token counters found in request or response payloads.
    pub usage: TokenUsage,
    /// Anthropic message id when present.
    pub message_id: Option<String>,
    /// Provider model name.
    pub model: Option<String>,
    /// Anthropic API version header when present.
    pub anthropic_version: Option<String>,
    /// Provider event type strings found in response JSON/SSE payloads.
    pub event_types: Vec<String>,
}

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

pub(super) fn request_host(headers: &HeaderMap, uri: &http::Uri) -> Option<String> {
    uri.host()
        .map(str::to_owned)
        .or_else(|| header(headers, HOST.as_str()).map(str::to_owned))
        .map(|host| normalize_host(&host))
}

fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub(super) fn flow_server_name(flow: &FlowContext) -> Option<String> {
    match &flow.protocol {
        TransparentProtocol::TlsHttp { server_name } => Some(normalize_host(server_name)),
        _ => None,
    }
}

pub(super) fn tool_result_output(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(tool_result_part)
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(_) => tool_result_part(content).unwrap_or_default(),
        _ => String::new(),
    }
}

fn tool_result_part(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    if object.get("type").and_then(Value::as_str) == Some("image") {
        let media_type = object
            .get("source")
            .and_then(Value::as_object)
            .and_then(|source| source.get("media_type"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(format!("[image attachment: {media_type}]"));
    }
    // Structured tool results are model-visible audit content just like text
    // results. Preserve their complete captured JSON when no text projection
    // exists; the event content mode still redacts this output unless the
    // configured audit policy explicitly allows plaintext retention. The HTTP
    // capture boundary provides the payload size limit.
    json_to_text(value, MAX_PARSE_DEPTH).or_else(|| serde_json::to_string(value).ok())
}

pub(super) fn best_usage(values: &[Value]) -> Option<TokenUsage> {
    let usages = values
        .iter()
        .flat_map(|value| find_usage(value, MAX_PARSE_DEPTH))
        .collect::<Vec<_>>();
    if usages.is_empty() {
        return None;
    }

    // Streaming Messages responses report input-side counters in
    // `message_start` and cumulative output in `message_delta`.
    let mut combined = TokenUsage::default();
    for usage in usages {
        combined.input_tokens = combined.input_tokens.max(usage.input_tokens);
        combined.output_tokens = combined.output_tokens.max(usage.output_tokens);
        combined.cache_read_tokens = combined.cache_read_tokens.max(usage.cache_read_tokens);
        combined.cache_write_tokens = combined.cache_write_tokens.max(usage.cache_write_tokens);
        combined.reasoning_tokens = combined.reasoning_tokens.max(usage.reasoning_tokens);
    }
    Some(TokenUsage::from_parts(
        combined.input_tokens,
        combined.cache_read_tokens,
        combined.cache_write_tokens,
        combined.output_tokens,
        combined.reasoning_tokens,
    ))
}

/// Estimates token usage from the visible content of both conversations:
/// one token per four bytes of trimmed entry text, tool names included.
pub(super) fn estimated_visible_usage(
    request_conversation: &Conversation,
    response_conversation: &Conversation,
) -> TokenUsage {
    let input_tokens = estimate_visible_tokens(request_conversation);
    let output_tokens = estimate_visible_tokens(response_conversation);
    TokenUsage::from_parts(input_tokens, 0, 0, output_tokens, 0)
}

fn estimate_visible_tokens(conversation: &Conversation) -> i64 {
    let byte_count = conversation
        .entries
        .iter()
        .map(|entry| {
            let name = match entry.role {
                EntryRole::ToolCall => entry.name.as_deref().map_or(0, str::len),
                _ => 0,
            };
            name.saturating_add(entry.text.trim().len())
        })
        .fold(0_usize, usize::saturating_add);
    if byte_count == 0 {
        return 0;
    }
    i64::try_from(byte_count.div_ceil(4)).unwrap_or(i64::MAX)
}

fn find_usage(value: &Value, depth: usize) -> Vec<TokenUsage> {
    if depth == 0 {
        return Vec::new();
    }

    match value {
        Value::Object(object) => {
            let mut found = Vec::new();
            if let Some(usage) = usage_from_object(object) {
                found.push(usage);
            }
            if let Some(usage) = object
                .get("usage")
                .and_then(Value::as_object)
                .and_then(usage_from_object)
            {
                found.push(usage);
            }
            for child in object.values() {
                found.extend(find_usage(child, depth.saturating_sub(1)));
            }
            found
        }
        Value::Array(items) => items
            .iter()
            .flat_map(|item| find_usage(item, depth.saturating_sub(1)))
            .collect(),
        _ => Vec::new(),
    }
}

fn usage_from_object(object: &serde_json::Map<String, Value>) -> Option<TokenUsage> {
    let input = int_field(object, "input_tokens").unwrap_or(0);
    let output = int_field(object, "output_tokens").unwrap_or(0);
    let native_cache_read = int_field(object, "cache_read_input_tokens");
    let native_cache_write = int_field(object, "cache_creation_input_tokens");
    // Native Messages usage keeps cache counters outside `input_tokens`.
    // OpenAI-style details from compatible gateways count them inside it.
    let detail_cache_read = native_cache_read
        .is_none()
        .then(|| nested_int_field(object, "input_tokens_details", "cached_tokens"))
        .flatten()
        .unwrap_or(0);
    let detail_cache_write = native_cache_write
        .is_none()
        .then(|| nested_int_field(object, "input_tokens_details", "cache_creation_tokens"))
        .flatten()
        .unwrap_or(0);
    let cache_read = native_cache_read.unwrap_or(detail_cache_read);
    let cache_write = native_cache_write.unwrap_or(detail_cache_write);
    let input = input
        .saturating_sub(detail_cache_read)
        .saturating_sub(detail_cache_write)
        .max(0);
    let reasoning = nested_int_field(object, "output_tokens_details", "thinking_tokens")
        .or_else(|| int_field(object, "thinking_tokens"))
        .or_else(|| int_field(object, "reasoning_tokens"))
        .unwrap_or(0);

    let usage = TokenUsage::from_parts(input, cache_read, cache_write, output, reasoning);
    (!usage.is_empty()).then_some(usage)
}

fn int_field(object: &serde_json::Map<String, Value>, key: &str) -> Option<i64> {
    object
        .get(key)
        .and_then(Value::as_i64)
        .filter(|value| *value >= 0)
}

fn nested_int_field(
    object: &serde_json::Map<String, Value>,
    parent: &str,
    child: &str,
) -> Option<i64> {
    object
        .get(parent)
        .and_then(Value::as_object)
        .and_then(|nested| int_field(nested, child))
}

pub(super) fn first_model(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "model"))
}

pub(super) fn first_stop_reason(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "stop_reason"))
}

pub(super) struct TurnMessageUuids {
    pub(super) human: Option<String>,
    pub(super) assistant: Option<String>,
}

pub(super) fn turn_message_uuids(payload: &Value) -> TurnMessageUuids {
    let turn_message_uuids = payload.get("turn_message_uuids").and_then(Value::as_object);
    TurnMessageUuids {
        human: turn_message_uuids
            .and_then(|object| object.get("human_message_uuid"))
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(str::to_owned),
        assistant: turn_message_uuids
            .and_then(|object| object.get("assistant_message_uuid"))
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(str::to_owned),
    }
}

pub(super) fn claude_web_file_uuids(payload: &Value) -> Vec<String> {
    let mut file_uuids = Vec::new();
    let Some(files) = payload.get("files").and_then(Value::as_array) else {
        return file_uuids;
    };
    for file_uuid in files {
        let Some(file_uuid) = file_uuid.as_str().and_then(non_empty_trimmed) else {
            continue;
        };
        if !file_uuids.iter().any(|existing| existing == file_uuid) {
            file_uuids.push(file_uuid.to_owned());
        }
    }
    file_uuids
}

fn collect_string_field(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(object) => object
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
            .or_else(|| {
                object
                    .values()
                    .find_map(|child| collect_string_field(child, key))
            }),
        Value::Array(items) => items
            .iter()
            .find_map(|child| collect_string_field(child, key)),
        _ => None,
    }
}

pub(super) fn event_types(value: &Value) -> Vec<String> {
    let mut event_types = Vec::new();
    collect_event_types(value, MAX_PARSE_DEPTH, &mut event_types);
    event_types
}

fn collect_event_types(value: &Value, depth: usize, event_types: &mut Vec<String>) {
    if depth == 0 {
        return;
    }

    match value {
        Value::Object(object) => {
            if let Some(event_type) = object.get("type").and_then(Value::as_str) {
                event_types.push(event_type.to_owned());
            }
            for child in object.values() {
                collect_event_types(child, depth.saturating_sub(1), event_types);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_event_types(item, depth.saturating_sub(1), event_types);
            }
        }
        _ => {}
    }
}

struct ResolvedAnthropicSessionId {
    id: String,
    source: AnthropicSessionIdSource,
}

fn anthropic_session_id(
    headers: &HeaderMap,
    payload: &Value,
    host: &str,
) -> ResolvedAnthropicSessionId {
    provider_session_id(headers, payload).map_or_else(
        || ResolvedAnthropicSessionId {
            id: format!(
                "anthropic-unattributed-{}",
                sanitize_session_component(host)
            ),
            source: AnthropicSessionIdSource::Unattributed,
        },
        |id| ResolvedAnthropicSessionId {
            id,
            source: AnthropicSessionIdSource::Provider,
        },
    )
}

fn provider_session_id(headers: &HeaderMap, payload: &Value) -> Option<String> {
    header(headers, "x-claude-code-session-id")
        .or_else(|| header(headers, "x-claude-session-id"))
        .map(str::to_owned)
        .or_else(|| metadata_session_id(payload))
        .or_else(|| collect_string_field(payload, "session_id"))
        .or_else(|| header(headers, "session-id").map(str::to_owned))
        .or_else(|| header(headers, "thread-id").map(str::to_owned))
        .or_else(|| collect_string_field(payload, "thread_id"))
        .or_else(|| collect_string_field(payload, "conversation_id"))
}

fn metadata_session_id(payload: &Value) -> Option<String> {
    let user_id = payload
        .get("metadata")
        .and_then(Value::as_object)
        .and_then(|metadata| metadata.get("user_id"))
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)?;
    serde_json::from_str::<Value>(user_id)
        .ok()
        .and_then(|metadata| {
            metadata
                .get("session_id")
                .and_then(Value::as_str)
                .and_then(non_empty_trimmed)
                .map(str::to_owned)
        })
}

fn sanitize_session_component(value: &str) -> String {
    let mut component = String::new();
    let mut last_was_separator = false;
    for character in value.chars().flat_map(char::to_lowercase) {
        if character.is_ascii_alphanumeric() {
            component.push(character);
            last_was_separator = false;
        } else if !last_was_separator {
            component.push('-');
            last_was_separator = true;
        }
    }
    component.trim_matches('-').to_owned()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(non_empty_trimmed)
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

pub(super) fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
}

pub(super) const fn transport_name(protocol: &TransparentProtocol) -> &'static str {
    match protocol {
        TransparentProtocol::PlainHttp => "http",
        TransparentProtocol::TlsHttp { .. } => "https",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
    };
    use abyss_plugin_protocol::event::EntryRole;
    use http::{Request, Response};
    use serde_json::{Value, json};

    use super::{AnthropicSessionIdSource, parse_anthropic_messages_exchange};
    use crate::protocol::model::conversation::role_texts;

    #[test]
    fn parses_messages_json_without_harness_assumptions() {
        let exchange = json_exchange(
            "/v1/messages",
            &json!({
                "model": "claude-test",
                "messages": [{"role": "user", "content": "hello"}]
            }),
            &json!({
                "id": "msg_1",
                "model": "claude-test",
                "content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 3_i32, "output_tokens": 4_i32}
            }),
        );

        let parsed =
            parse_anthropic_messages_exchange(&exchange).expect("Anthropic Messages exchange");

        assert_eq!(parsed.host, "gateway.example");
        assert_eq!(parsed.session_id, "session-1");
        assert!(matches!(
            parsed.session_id_source,
            AnthropicSessionIdSource::Provider
        ));
        assert_eq!(
            role_texts(&parsed.request_conversation),
            [(EntryRole::User, "hello")]
        );
        assert_eq!(
            role_texts(&parsed.response_conversation),
            [(EntryRole::Assistant, "hi")]
        );
        assert_eq!(parsed.message_id.as_deref(), Some("msg_1"));
        assert_eq!(parsed.model.as_deref(), Some("claude-test"));
        assert_eq!(parsed.usage.input_tokens, 3);
        assert_eq!(parsed.usage.output_tokens, 4);
    }

    #[test]
    fn parses_messages_sse_usage_and_tool_call() {
        let request = json!({
            "model": "claude-test",
            "messages": [{"role": "user", "content": "run pwd"}]
        });
        let response = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_2\",",
            "\"model\":\"claude-test\",\"usage\":{\"input_tokens\":5}}}\n\n",
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":",
            "{\"type\":\"tool_use\",\"id\":\"tool-1\",\"name\":\"Bash\",\"input\":{}}}\n\n",
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":",
            "{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"command\\\":\\\"pwd\\\"}\"}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":2}}\n\n"
        );
        let exchange = sse_exchange("/v1/messages", &request, response.as_bytes());

        let parsed = parse_anthropic_messages_exchange(&exchange).expect("Anthropic SSE exchange");

        assert_eq!(parsed.message_id.as_deref(), Some("msg_2"));
        assert_eq!(
            role_texts(&parsed.response_conversation),
            [(EntryRole::ToolCall, "{\"command\":\"pwd\"}")]
        );
        assert_eq!(parsed.usage.input_tokens, 5);
        assert_eq!(parsed.usage.output_tokens, 2);
    }

    #[test]
    fn keeps_messages_cache_counters_disjoint_from_input() {
        let request = json!({
            "model": "claude-test",
            "messages": [{"role": "user", "content": "continue"}]
        });
        let response = concat!(
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_3\",",
            "\"model\":\"claude-test\",\"usage\":{\"input_tokens\":2,",
            "\"cache_read_input_tokens\":77000,\"cache_creation_input_tokens\":400,",
            "\"output_tokens\":1}}}\n\n",
            "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":2,",
            "\"cache_read_input_tokens\":77000,\"cache_creation_input_tokens\":400,",
            "\"output_tokens\":150}}\n\n"
        );
        let exchange = sse_exchange("/v1/messages", &request, response.as_bytes());

        let parsed = parse_anthropic_messages_exchange(&exchange).expect("Anthropic SSE exchange");

        assert_eq!(parsed.usage.input_tokens, 2);
        assert_eq!(parsed.usage.cache_read_tokens, 77_000);
        assert_eq!(parsed.usage.cache_write_tokens, 400);
        assert_eq!(parsed.usage.output_tokens, 150);
        assert_eq!(parsed.usage.total_tokens, 77_552);
    }

    #[test]
    fn parses_tool_result_from_latest_user_message() {
        let exchange = json_exchange(
            "/v1/messages",
            &json!({
                "model": "claude-test",
                "messages": [
                    {"role": "assistant", "content": [
                        {"type": "tool_use", "id": "tool-1", "name": "Read", "input": {"path": "a"}}
                    ]},
                    {"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "tool-1", "content": "file contents"}
                    ]}
                ]
            }),
            &json!({
                "id": "msg-3",
                "content": [{"type": "text", "text": "done"}],
                "usage": {"input_tokens": 8_i32, "output_tokens": 1_i32}
            }),
        );

        let parsed = parse_anthropic_messages_exchange(&exchange).expect("tool-result exchange");

        assert_eq!(
            role_texts(&parsed.request_conversation),
            [
                (EntryRole::ToolCall, "{\"path\":\"a\"}"),
                (EntryRole::ToolResult, "file contents"),
            ]
        );
    }

    #[test]
    fn retains_unattributed_session_bucket_when_protocol_has_no_session_id() {
        let mut exchange = json_exchange(
            "/v1/messages",
            &json!({
                "model": "claude-test",
                "messages": [{"role": "user", "content": "hello"}]
            }),
            &json!({
                "content": [{"type": "text", "text": "hi"}],
                "usage": {"input_tokens": 1_i32, "output_tokens": 1_i32}
            }),
        );
        exchange.request.headers_mut().remove("session-id");

        let parsed = parse_anthropic_messages_exchange(&exchange).expect("unattributed exchange");

        assert!(matches!(
            parsed.session_id_source,
            AnthropicSessionIdSource::Unattributed
        ));
        assert_eq!(parsed.session_id, "anthropic-unattributed-gateway-example");
    }

    const CLAUDE_CODE_TURN_13: &str = "x-anthropic-billing-header: cc_version=2.1.293.af3; cc_entrypoint=cli; cch=71184; cc_prev_req=req_011Cfp63WyExutpXM23Swg97; cc_prompt_id=a7e7449e-3401-4091-9857-98c73e217ce3; cc_turn_origin=human; cc_prompt_index=13; cc_turn_index=13;";

    /// Trimmed Claude Code 2.1.293 request bodies of one user turn
    /// (`cc_turn_index=13`): a `continue` that failed with `thread_not_found`,
    /// its `create` replay under a new `cc_prompt_id`, and a later
    /// tool-result-only `continue`.
    fn claude_code_turn_13_requests() -> [Value; 3] {
        [
            json!({
                "model": "claude-opus-5-5",
                "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.293.af3; cc_entrypoint=cli; cch=3ceb5; cc_prev_req=req_011Cfp5Uve7sxQqhVCrv4MHM; cc_prompt_id=100bbd47-4661-4476-a802-eb9bad30b029; cc_turn_origin=human; cc_prompt_index=13; cc_turn_index=13;"}],
                "messages": [
                    {"role": "user", "content": "look at the thread field"},
                    {"role": "system", "content": [{"type": "text", "text": "<total_tokens>14998716 tokens left</total_tokens>"}]}
                ],
                "thread": {"type": "continue", "previous_message_id": "msg_011Cfp5UzgwXz5ZQcfs9WXCP"},
                "stream": true
            }),
            json!({
                "model": "claude-opus-5-5",
                "system": [
                    {"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.293.af3; cc_entrypoint=cli; cch=feaae; cc_prev_req=req_011Cfp5Uve7sxQqhVCrv4MHM; cc_prompt_id=a7e7449e-3401-4091-9857-98c73e217ce3; cc_turn_origin=human; cc_prompt_index=13; cc_turn_index=13;"},
                    {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."}
                ],
                "messages": [
                    {"role": "user", "content": "earlier prompt"},
                    {"role": "assistant", "content": [{"type": "text", "text": "earlier answer"}]},
                    {"role": "user", "content": "look at the thread field"},
                    {"role": "system", "content": [{"type": "text", "text": "<total_tokens>14998716 tokens left</total_tokens>"}]}
                ],
                "tools": [{"name": "Bash", "input_schema": {"type": "object"}}],
                "thread": {"type": "create"},
                "stream": true
            }),
            json!({
                "model": "claude-opus-5-5",
                "system": [{"type": "text", "text": CLAUDE_CODE_TURN_13}],
                "messages": [
                    {"role": "user", "content": [
                        {"tool_use_id": "toolu_01NTVfgULERMfiZJkqtEfMcX", "type": "tool_result", "content": "ok"}
                    ]},
                    {"role": "system", "content": [{"type": "text", "text": "<total_tokens>14998716 tokens left</total_tokens>"}]}
                ],
                "thread": {"type": "continue", "previous_message_id": "msg_011Cfp64Grx3HXuyQSqYibkp"},
                "stream": true
            }),
        ]
    }

    #[test]
    fn only_a_thread_continue_names_the_response_it_continues_after() {
        let parsed = claude_code_turn_13_requests().map(|request| {
            parse_anthropic_messages_exchange(&json_exchange("/v1/messages", &request, &json!({})))
                .expect("Claude Code exchange")
        });

        assert_eq!(
            parsed
                .each_ref()
                .map(|exchange| exchange.previous_response_id.as_deref()),
            [
                Some("msg_011Cfp5UzgwXz5ZQcfs9WXCP"),
                None,
                Some("msg_011Cfp64Grx3HXuyQSqYibkp"),
            ]
        );
    }

    #[test]
    fn response_id_is_the_message_id_of_the_conversation() {
        let request = json!({"messages": [{"role": "user", "content": "hello"}]});
        // A stream names its message in `message_start.message.id`.
        let streamed = parse_anthropic_messages_exchange(&sse_exchange(
            "/v1/messages",
            &request,
            concat!(
                "data: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"content\":[]}}\n\n",
                "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
                "data: {\"type\":\"message_stop\"}\n\n"
            )
            .as_bytes(),
        ))
        .expect("SSE exchange");
        assert_eq!(streamed.message_id.as_deref(), Some("m1"));
        assert_eq!(streamed.response_conversation.entries[0].text, "hi");

        // A whole message names itself in its top-level `id`; an id in the
        // request is never the response's.
        let whole = parse_anthropic_messages_exchange(&json_exchange(
            "/v1/messages",
            &json!({"id": "msg_request", "messages": [{"role": "user", "content": "hello"}]}),
            &json!({"id": "m2", "type": "message", "content": [{"type": "text", "text": "hi"}]}),
        ))
        .expect("JSON exchange");
        assert_eq!(whole.message_id.as_deref(), Some("m2"));
        assert_eq!(whole.response_conversation.entries[0].text, "hi");
    }

    #[test]
    fn rejects_non_dialogue_payload() {
        let exchange = json_exchange(
            "/v1/messages",
            &json!({"model": "claude-test", "metadata": {"operation": "bootstrap"}}),
            &json!({}),
        );

        assert!(parse_anthropic_messages_exchange(&exchange).is_none());
    }

    fn json_exchange(path: &str, request: &Value, response: &Value) -> HttpExchange {
        exchange(
            path,
            request,
            "application/json",
            serde_json::to_vec(response).unwrap(),
        )
    }

    fn sse_exchange(path: &str, request: &Value, response: &[u8]) -> HttpExchange {
        exchange(path, request, "text/event-stream", response.to_vec())
    }

    fn exchange(
        path: &str,
        request_body: &Value,
        response_content_type: &str,
        response_body: Vec<u8>,
    ) -> HttpExchange {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("host", "gateway.example")
            .header("session-id", "session-1")
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .body(CapturedBody::from_bytes(
                serde_json::to_vec(request_body).unwrap().into(),
            ))
            .unwrap();
        let response = Response::builder()
            .header("content-type", response_content_type)
            .body(CapturedBody::from_bytes(response_body.into()))
            .unwrap();
        HttpExchange::new(flow(), request, response)
    }

    fn flow() -> FlowContext {
        FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18090)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::TlsHttp {
                server_name: "gateway.example".to_owned(),
            },
        )
    }
}
