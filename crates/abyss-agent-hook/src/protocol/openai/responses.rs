//! OpenAI Responses and Chat Completions exchange parser.
//!
//! The parser consumes exchanges already selected by protocol detection and
//! extracts wire-level content without identifying the calling Harness.

use abyss_mitm::{
    FlowContext, HttpExchange, TransparentProtocol, WebSocketDirection, WebSocketMessage,
};
use http::{HeaderMap, header::HOST};
use serde_json::Value;

use crate::{
    protocol::model::conversation::ConversationProjection,
    protocol::model::digest::sha256_hex,
    protocol::model::image::{ParsedImageAttachment, extract_openai_request_images},
    protocol::model::text::{MAX_PARSE_DEPTH, json_to_text, non_empty_trimmed},
    protocol::model::tool::ParsedToolEvent,
    protocol::model::usage::TokenUsage,
    protocol::openai::{
        conversation::{OpenAiRequest, OpenAiResponse},
        websocket::{OpenAiWebSocketFrame, OpenAiWebSocketResponse, is_terminal_event},
    },
    protocol::sse::ResponseDocuments,
};

/// Wire-level values extracted from one OpenAI-compatible interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedOpenAiExchange {
    /// Normalized request host.
    pub host: String,
    /// Request path used to distinguish OpenAI/Codex API families.
    pub path: String,
    /// HTTP method.
    pub method: String,
    /// Transport observed by `abyss-mitm`: `http`, `https`, or `unknown`.
    pub transport: &'static str,
    /// Session/thread id used to group turns. A flow-derived fallback is used
    /// when Codex/OpenAI headers do not expose one.
    pub session_id: String,
    /// Hash of method, host, path, and request body for fallback correlation.
    pub request_hash: String,
    /// Structured request messages decoded from the request body.
    pub request_conversation: abyss_plugin_protocol::event::Conversation,
    /// Structured response messages assembled from the response documents.
    pub response_conversation: abyss_plugin_protocol::event::Conversation,
    /// User-visible prompt/input fragments derived from the request messages.
    pub request_texts: Vec<String>,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// Model-visible response fragments derived from the response messages.
    pub response_texts: Vec<String>,
    /// Best token counters found in request or response payloads.
    pub usage: TokenUsage,
    /// Provider response id when present.
    pub response_id: Option<String>,
    /// Previous provider response id for conversation linkage.
    pub previous_response_id: Option<String>,
    /// Stable logical turn id carried by request/item metadata when present.
    pub protocol_turn_id: Option<String>,
    /// Tool results carried by the provider request side of this exchange.
    pub request_tool_events: Vec<ParsedToolEvent>,
    /// Tool calls carried by the provider response side of this exchange.
    pub response_tool_events: Vec<ParsedToolEvent>,
    /// Provider model name.
    pub model: Option<String>,
    /// Provider event type strings found in response JSON/SSE payloads.
    pub event_types: Vec<String>,
}

/// Parses an OpenAI Responses or Chat Completions exchange without Harness assumptions.
#[must_use]
pub fn parse_openai_exchange(exchange: &HttpExchange) -> Option<ParsedOpenAiExchange> {
    let host = request_host(exchange.request.headers(), exchange.request.uri())?;
    let path = exchange.request.uri().path();
    // OpenAI responses may be a single JSON object or an SSE stream where each
    // `data:` line carries a JSON event. Normalize both shapes into a list of
    // JSON values and run the same extractors over that list.
    let request_json = exchange.request.body().json();
    let request = OpenAiRequest::parse(request_json, exchange.request.body().truncated());
    let request_texts = request.texts();
    let request_images = request_json.map_or_else(Vec::new, extract_openai_request_images);
    let request_tool_events = request_json.map_or_else(Vec::new, extract_request_tool_events);
    let response_documents = ResponseDocuments::decode(exchange.response.body());
    let response_values = response_documents.values;
    let response = OpenAiResponse::assemble(&response_values, response_documents.incomplete);
    let response_texts = response.texts();
    let response_tool_events = response_values
        .iter()
        .flat_map(extract_response_tool_events)
        .collect::<Vec<_>>();
    // Providers usually report token usage on the final response event. Some
    // request styles may include useful usage-like fields on the request, so use
    // those as a fallback only when response usage is absent.
    //
    // Request body capture is policy bounded in the MITM relay. Large Codex
    // turns may therefore arrive here with a truncated, non-JSON request body
    // while the response may also be truncated before the final usage event.
    // Treat truncation itself as evidence that an audit-relevant exchange
    // occurred, even when the retained prefixes do not parse into text or usage.
    let usage = best_usage(&response_values).unwrap_or_else(|| {
        request_json
            .and_then(|json| best_usage(std::slice::from_ref(json)))
            .unwrap_or_default()
    });
    let body_was_truncated =
        exchange.request.body().truncated() || exchange.response.body().truncated();
    if request_texts.is_empty()
        && request_images.is_empty()
        && request_tool_events.is_empty()
        && response_texts.is_empty()
        && response_tool_events.is_empty()
        && usage.is_empty()
        && !body_was_truncated
    {
        return None;
    }

    let response_id = first_response_id(&response_values)
        .or_else(|| request_json.and_then(|json| first_response_id(std::slice::from_ref(json))));
    let previous_response_id = request_json
        .and_then(|json| string_field(json, "previous_response_id"))
        .map(str::to_owned);
    let protocol_turn_id = request_json
        .and_then(protocol_turn_id)
        .or_else(|| response_values.iter().find_map(protocol_turn_id))
        .or_else(|| protocol_turn_id_from_headers(exchange.request.headers()));
    let model = first_model(&response_values)
        .or_else(|| request_json.and_then(|json| string_field(json, "model").map(str::to_owned)));
    let headers = exchange.request.headers();
    let request_hash = sha256_hex(&format!(
        "{}\0{}\0{}\0{}",
        exchange.request.method(),
        host,
        path,
        String::from_utf8_lossy(exchange.request.body().bytes())
    ));

    Some(ParsedOpenAiExchange {
        host,
        path: path.to_owned(),
        method: exchange.request.method().to_string(),
        transport: transport_name(&exchange.flow.protocol),
        session_id: session_id(headers).unwrap_or_else(|| format!("flow-{}", &request_hash[..16])),
        request_hash,
        request_conversation: request.conversation(),
        response_conversation: response.conversation(),
        request_texts,
        request_images,
        response_texts,
        usage,
        response_id,
        previous_response_id,
        protocol_turn_id,
        request_tool_events,
        response_tool_events,
        model,
        event_types: response_values.iter().flat_map(event_types).collect(),
    })
}

/// Decodes one OpenAI Responses WebSocket frame after a successful HTTP 101.
///
/// A frame whose payload is not JSON is reported as undecodable so the turn
/// side it belongs to is marked partial. A decodable frame that carries no
/// request content, response content, tools, usage, or terminal state, such as
/// `response.created`, is irrelevant and leaves the pending turn untouched.
/// Server frames keep their decoded document because the turn's response is
/// assembled from the complete stream when the terminal event arrives.
#[must_use]
pub fn parse_openai_websocket_message(message: &WebSocketMessage) -> OpenAiWebSocketFrame {
    let Some(payload) = websocket_json_payload(message) else {
        return OpenAiWebSocketFrame::Undecodable(message.direction);
    };
    // A frame that cannot be attributed to a host is not a content failure.
    let Some(host) = request_host(
        message.upgrade_request.headers(),
        message.upgrade_request.uri(),
    )
    .or_else(|| flow_server_name(&message.flow)) else {
        return OpenAiWebSocketFrame::Irrelevant;
    };
    let path = message.upgrade_request.uri().path();
    let is_client_message = matches!(message.direction, WebSocketDirection::ClientToServer);
    let request_payload = payload.get("response").unwrap_or(&payload);
    let (request, request_images, request_tool_events) = if is_client_message {
        (
            OpenAiRequest::parse(Some(request_payload), false),
            extract_openai_request_images(request_payload),
            extract_request_tool_events(request_payload),
        )
    } else {
        (OpenAiRequest::parse(None, false), Vec::new(), Vec::new())
    };
    let (response_tool_events, usage) = if is_client_message {
        (Vec::new(), TokenUsage::default())
    } else {
        (
            extract_response_tool_events(&payload),
            best_usage(std::slice::from_ref(&payload)).unwrap_or_default(),
        )
    };
    let relevant = if is_client_message {
        !request.is_empty() || !request_images.is_empty() || !request_tool_events.is_empty()
    } else {
        !OpenAiResponse::assemble(std::slice::from_ref(&payload), false).is_empty()
            || !response_tool_events.is_empty()
            || !usage.is_empty()
            || string_field(&payload, "type").is_some_and(is_terminal_event)
    };
    if !relevant {
        return OpenAiWebSocketFrame::Irrelevant;
    }

    let Ok(payload_text) = serde_json::to_string(&payload) else {
        return OpenAiWebSocketFrame::Undecodable(message.direction);
    };
    let request_hash = sha256_hex(&format!(
        "{:?}\0{}\0{}\0{}\0{}",
        message.direction, host, path, message.sequence, payload_text
    ));
    let exchange = ParsedOpenAiExchange {
        host,
        path: path.to_owned(),
        method: message.upgrade_request.method().to_string(),
        transport: transport_name(&message.flow.protocol),
        session_id: websocket_session_id(message, &payload),
        request_hash,
        request_conversation: request.conversation(),
        // The accumulator assembles the response once the turn terminates.
        response_conversation: ConversationProjection::empty(),
        request_texts: request.texts(),
        request_images,
        response_texts: Vec::new(),
        usage,
        response_id: if is_client_message {
            None
        } else {
            first_response_id(std::slice::from_ref(&payload))
        },
        previous_response_id: string_field(&payload, "previous_response_id").map(str::to_owned),
        protocol_turn_id: protocol_turn_id(&payload),
        request_tool_events,
        response_tool_events,
        model: first_model(std::slice::from_ref(&payload)),
        event_types: if is_client_message {
            Vec::new()
        } else {
            event_types(&payload)
        },
    };
    if is_client_message {
        return OpenAiWebSocketFrame::Request(Box::new(exchange));
    }
    let byte_len = message.text.as_ref().map_or_else(
        || message.binary.as_deref().map_or(0, <[u8]>::len),
        String::len,
    );
    OpenAiWebSocketFrame::Response(Box::new(OpenAiWebSocketResponse {
        exchange,
        document: payload,
        byte_len,
    }))
}

fn request_host(headers: &HeaderMap, uri: &http::Uri) -> Option<String> {
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

fn websocket_json_payload(message: &WebSocketMessage) -> Option<Value> {
    match (&message.text, &message.binary) {
        (Some(text), _) => serde_json::from_str(text).ok(),
        (None, Some(bytes)) => serde_json::from_slice(bytes).ok(),
        (None, None) => None,
    }
}

fn flow_server_name(flow: &FlowContext) -> Option<String> {
    match &flow.protocol {
        TransparentProtocol::TlsHttp { server_name } => Some(normalize_host(server_name)),
        _ => None,
    }
}

fn websocket_session_id(message: &WebSocketMessage, payload: &Value) -> String {
    header(message.upgrade_request.headers(), "session-id")
        .or_else(|| header(message.upgrade_request.headers(), "thread-id"))
        .map(str::to_owned)
        .or_else(|| collect_string_field(payload, "session_id"))
        .or_else(|| collect_string_field(payload, "thread_id"))
        .or_else(|| collect_string_field(payload, "conversation_id"))
        .or_else(|| collect_string_field(payload, "response_id"))
        .or_else(|| first_response_id(std::slice::from_ref(payload)))
        .unwrap_or_else(|| format!("flow-{}", message.flow.flow_id))
}

fn protocol_turn_id_from_headers(headers: &HeaderMap) -> Option<String> {
    header(headers, "x-codex-turn-metadata")
        .and_then(protocol_turn_id_from_metadata_json)
        .or_else(|| {
            header(headers, "x-codex-turn-id")
                .and_then(non_empty_trimmed)
                .map(str::to_owned)
        })
}

fn protocol_turn_id(payload: &Value) -> Option<String> {
    collect_non_empty_string_field(payload, "turn_id").or_else(|| {
        collect_non_empty_string_field(payload, "x-codex-turn-metadata")
            .and_then(|metadata| protocol_turn_id_from_metadata_json(&metadata))
    })
}

fn protocol_turn_id_from_metadata_json(metadata: &str) -> Option<String> {
    serde_json::from_str::<Value>(metadata)
        .ok()
        .and_then(|metadata| collect_non_empty_string_field(&metadata, "turn_id"))
}

fn extract_request_tool_events(payload: &Value) -> Vec<ParsedToolEvent> {
    let mut events = Vec::new();
    collect_request_tool_events(payload, MAX_PARSE_DEPTH, &mut events);
    events
}

fn collect_request_tool_events(value: &Value, depth: usize, events: &mut Vec<ParsedToolEvent>) {
    if depth == 0 {
        return;
    }

    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("custom_tool_call_output" | "function_call_output")
            ) && let Some(output) = object
                .get("output")
                .and_then(|output| json_to_text(output, depth.saturating_sub(1)))
                .and_then(|output| non_empty_trimmed(&output).map(str::to_owned))
            {
                push_unique_tool_event(
                    events,
                    ParsedToolEvent::ToolResult {
                        call_id: optional_object_string(object, "call_id"),
                        output,
                    },
                );
            } else {
                for child in object.values() {
                    collect_request_tool_events(child, depth.saturating_sub(1), events);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_request_tool_events(item, depth.saturating_sub(1), events);
            }
        }
        _ => {}
    }
}

fn extract_response_tool_events(payload: &Value) -> Vec<ParsedToolEvent> {
    let mut events = Vec::new();
    collect_response_tool_events(payload, MAX_PARSE_DEPTH, &mut events);
    events
}

fn collect_response_tool_events(value: &Value, depth: usize, events: &mut Vec<ParsedToolEvent>) {
    if depth == 0 {
        return;
    }

    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("custom_tool_call" | "function_call")
            ) && let Some(input) = object
                .get("input")
                .or_else(|| object.get("arguments"))
                .and_then(|input| json_to_text(input, depth.saturating_sub(1)))
                .and_then(|input| non_empty_trimmed(&input).map(str::to_owned))
            {
                push_unique_tool_event(
                    events,
                    ParsedToolEvent::ToolCall {
                        item_id: optional_object_string(object, "id"),
                        call_id: optional_object_string(object, "call_id"),
                        name: optional_object_string(object, "name"),
                        input,
                    },
                );
            } else {
                for child in object.values() {
                    collect_response_tool_events(child, depth.saturating_sub(1), events);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_response_tool_events(item, depth.saturating_sub(1), events);
            }
        }
        _ => {}
    }
}

fn optional_object_string(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
        .map(str::to_owned)
}

fn push_unique_tool_event(events: &mut Vec<ParsedToolEvent>, event: ParsedToolEvent) {
    if !events.contains(&event) {
        events.push(event);
    }
}

fn best_usage(values: &[Value]) -> Option<TokenUsage> {
    // Streaming responses can contain several partial usage objects. Prefer the
    // one with the largest total because final events tend to be cumulative.
    values
        .iter()
        .flat_map(|value| find_usage(value, MAX_PARSE_DEPTH))
        .max_by_key(|usage| usage.total_tokens)
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
    // Accept both Responses API names and Chat Completions legacy names. Unknown
    // or negative counters are ignored so one malformed field does not poison
    // the whole exchange.
    let input = int_field(object, "input_tokens").or_else(|| int_field(object, "prompt_tokens"));
    let output =
        int_field(object, "output_tokens").or_else(|| int_field(object, "completion_tokens"));
    let cache_read = nested_int_field(object, "input_tokens_details", "cached_tokens")
        .or_else(|| nested_int_field(object, "prompt_tokens_details", "cached_tokens"))
        .unwrap_or(0);
    let cache_write = nested_int_field(object, "input_tokens_details", "cache_creation_tokens")
        .or_else(|| nested_int_field(object, "prompt_tokens_details", "cache_creation_tokens"))
        .unwrap_or(0);
    let reasoning = nested_int_field(object, "output_tokens_details", "reasoning_tokens")
        .or_else(|| int_field(object, "reasoning_tokens"))
        .unwrap_or(0);
    // OpenAI input counts include cached tokens and output counts include
    // reasoning; keep the cache counters disjoint from input.
    let input = input
        .unwrap_or(0)
        .saturating_sub(cache_read)
        .saturating_sub(cache_write)
        .max(0);
    let usage = TokenUsage::from_parts(
        input,
        cache_read,
        cache_write,
        output.unwrap_or(0),
        reasoning,
    );
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

fn first_response_id(values: &[Value]) -> Option<String> {
    values.iter().find_map(|value| {
        collect_string_field(value, "response_id").or_else(|| collect_response_id(value))
    })
}

fn collect_response_id(value: &Value) -> Option<String> {
    match value {
        Value::Object(object) => {
            if let Some(id) = object.get("id").and_then(Value::as_str)
                && id.starts_with("resp")
            {
                return Some(id.to_owned());
            }
            object.values().find_map(collect_response_id)
        }
        Value::Array(items) => items.iter().find_map(collect_response_id),
        _ => None,
    }
}

fn first_model(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "model"))
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

fn collect_non_empty_string_field(value: &Value, key: &str) -> Option<String> {
    match value {
        Value::Object(object) => object
            .get(key)
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(str::to_owned)
            .or_else(|| {
                object
                    .values()
                    .find_map(|child| collect_non_empty_string_field(child, key))
            }),
        Value::Array(items) => items
            .iter()
            .find_map(|child| collect_non_empty_string_field(child, key)),
        _ => None,
    }
}

fn event_types(value: &Value) -> Vec<String> {
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

fn session_id(headers: &HeaderMap) -> Option<String> {
    header(headers, "session-id")
        .or_else(|| header(headers, "thread-id"))
        .map(str::to_owned)
        .or_else(|| metadata_header_value(headers, "session_id"))
        .or_else(|| metadata_header_value(headers, "thread_id"))
}

fn metadata_header_value(headers: &HeaderMap, key: &str) -> Option<String> {
    let metadata = header(headers, "x-codex-turn-metadata")?;
    let value = serde_json::from_str::<Value>(metadata).ok()?;
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
        .map(str::to_owned)
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(non_empty_trimmed)
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
}

const fn transport_name(protocol: &TransparentProtocol) -> &'static str {
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
        WebSocketDirection, WebSocketMessage,
    };
    use http::{Request, Response};
    use serde_json::{Value, json};

    use super::{OpenAiWebSocketFrame, parse_openai_exchange, parse_openai_websocket_message};

    #[test]
    fn parses_responses_json_without_harness_assumptions() {
        let exchange = json_exchange(
            "/v1/responses",
            &json!({
                "model": "gpt-5",
                "input": [{"role": "user", "content": "hello"}]
            }),
            &json!({
                "id": "resp-1",
                "model": "gpt-5",
                "output": [{"content": [{"type": "output_text", "text": "hi"}]}],
                "usage": {
                    "input_tokens": 3_i32,
                    "output_tokens": 4_i32,
                    "total_tokens": 7_i32
                }
            }),
        );

        let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

        assert_eq!(parsed.host, "gateway.example");
        assert_eq!(parsed.session_id, "session-1");
        assert_eq!(parsed.request_texts, vec!["hello"]);
        assert_eq!(parsed.response_texts, vec!["hi"]);
        assert_eq!(parsed.response_id.as_deref(), Some("resp-1"));
        assert_eq!(parsed.model.as_deref(), Some("gpt-5"));
        assert_eq!(parsed.usage.total_tokens, 7);
    }

    #[test]
    fn parses_chat_completions_shape() {
        let exchange = json_exchange(
            "/v1/chat/completions",
            &json!({
                "model": "compatible-model",
                "messages": [{"role": "user", "content": "hello gateway"}]
            }),
            &json!({
                "id": "chatcmpl-1",
                "model": "compatible-model",
                "choices": [{"message": {"role": "assistant", "content": "hello user"}}],
                "usage": {
                    "prompt_tokens": 2_i32,
                    "completion_tokens": 3_i32,
                    "total_tokens": 5_i32
                }
            }),
        );

        let parsed = parse_openai_exchange(&exchange).expect("chat completions exchange");

        assert_eq!(parsed.request_texts, vec!["hello gateway"]);
        assert_eq!(parsed.response_texts, vec!["hello user"]);
        assert_eq!(parsed.usage.input_tokens, 2);
        assert_eq!(parsed.usage.output_tokens, 3);
    }

    #[test]
    fn removes_cached_tokens_from_input() {
        let exchange = json_exchange(
            "/v1/responses",
            &json!({
                "model": "gpt-5",
                "input": [{"role": "user", "content": "hello"}]
            }),
            &json!({
                "id": "resp-2",
                "model": "gpt-5",
                "output": [{"content": [{"type": "output_text", "text": "hi"}]}],
                "usage": {
                    "input_tokens": 1000_i32,
                    "input_tokens_details": {"cached_tokens": 900_i32},
                    "output_tokens": 50_i32,
                    "output_tokens_details": {"reasoning_tokens": 20_i32},
                    "total_tokens": 1050_i32
                }
            }),
        );

        let parsed = parse_openai_exchange(&exchange).expect("OpenAI exchange");

        assert_eq!(parsed.usage.input_tokens, 100);
        assert_eq!(parsed.usage.cache_read_tokens, 900);
        assert_eq!(parsed.usage.output_tokens, 50);
        assert_eq!(parsed.usage.reasoning_tokens, 20);
        assert_eq!(parsed.usage.total_tokens, 1050);
    }

    #[test]
    fn parses_responses_sse_and_tool_call() {
        let request = json!({
            "model": "gpt-test",
            "input": [{"role": "user", "content": "run pwd"}]
        });
        let response = concat!(
            "data: {\"type\":\"response.output_item.done\",\"item\":",
            "{\"type\":\"function_call\",\"id\":\"item-1\",\"call_id\":\"call-1\",",
            "\"name\":\"shell\",\"arguments\":\"{\\\"command\\\":\\\"pwd\\\"}\"}}\n\n",
            "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-2\",",
            "\"usage\":{\"input_tokens\":4,\"output_tokens\":2,\"total_tokens\":6}}}\n\n"
        );
        let exchange = exchange(
            "/v1/responses",
            &request,
            "text/event-stream",
            response.as_bytes().to_vec(),
        );

        let parsed = parse_openai_exchange(&exchange).expect("SSE exchange");

        assert_eq!(parsed.response_id.as_deref(), Some("resp-2"));
        assert_eq!(parsed.response_tool_events.len(), 1);
        assert_eq!(parsed.usage.total_tokens, 6);
        assert!(
            parsed
                .event_types
                .iter()
                .any(|event_type| event_type == "response.completed")
        );
    }

    #[test]
    fn truncated_exchange_is_retained_without_parseable_content() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("host", "gateway.example")
            .body(CapturedBody::from_truncated_bytes(
                b"{\"input\":".to_vec().into(),
            ))
            .unwrap();
        let response = Response::new(CapturedBody::from_bytes(Vec::new().into()));
        let exchange = HttpExchange::new(flow(), request, response);

        let parsed = parse_openai_exchange(&exchange).expect("truncated exchange");

        assert_eq!(parsed.request_texts, Vec::<String>::new());
        assert_eq!(parsed.response_texts, Vec::<String>::new());
    }

    #[test]
    fn parses_responses_websocket_message() {
        let message = WebSocketMessage::new(
            flow(),
            Request::builder()
                .method("GET")
                .uri("/v1/responses")
                .header("host", "gateway.example")
                .header("session-id", "session-1")
                .body(())
                .unwrap(),
            WebSocketDirection::ClientToServer,
            1,
            Some(
                json!({
                    "type": "response.create",
                    "response": {
                        "model": "gpt-test",
                        "input": [{"role": "user", "content": "hello websocket"}]
                    }
                })
                .to_string(),
            ),
            None,
        );

        let OpenAiWebSocketFrame::Request(parsed) = parse_openai_websocket_message(&message) else {
            panic!("WebSocket request message");
        };

        assert_eq!(parsed.session_id, "session-1");
        assert_eq!(parsed.request_texts, vec!["hello websocket"]);
    }

    #[test]
    fn websocket_frames_distinguish_undecodable_from_irrelevant() {
        let frame = |direction, body: &str| {
            parse_openai_websocket_message(&WebSocketMessage::new(
                flow(),
                Request::builder()
                    .method("GET")
                    .uri("/v1/responses")
                    .header("host", "gateway.example")
                    .body(())
                    .unwrap(),
                direction,
                1,
                Some(body.to_owned()),
                None,
            ))
        };

        assert!(matches!(
            frame(WebSocketDirection::ServerToClient, "{broken"),
            OpenAiWebSocketFrame::Undecodable(WebSocketDirection::ServerToClient)
        ));
        assert!(matches!(
            frame(
                WebSocketDirection::ServerToClient,
                r#"{"type":"response.created","response":{"id":"resp_1"}}"#
            ),
            OpenAiWebSocketFrame::Irrelevant
        ));
        assert!(matches!(
            frame(
                WebSocketDirection::ServerToClient,
                r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"hi"}"#
            ),
            OpenAiWebSocketFrame::Response(_)
        ));
        assert!(matches!(
            frame(
                WebSocketDirection::ClientToServer,
                r#"{"type":"response.cancel"}"#
            ),
            OpenAiWebSocketFrame::Irrelevant
        ));
    }

    #[test]
    fn streaming_response_text_is_not_repeated_by_terminal_events() {
        // The Responses stream republishes one completed answer through several
        // terminal events. The parser must report the answer once.
        let exchange = sse_exchange(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello "}"#,
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"world"}"#,
            r#"{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"Hello world"}"#,
            r#"{"type":"response.content_part.done","output_index":0,"content_index":0,"part":{"type":"output_text","text":"Hello world"}}"#,
            r#"{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world"}]}}"#,
            r#"{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5","output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"Hello world"}]}],"usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

        assert_eq!(parsed.response_texts, vec!["Hello world"]);
        assert_eq!(parsed.usage.total_tokens, 3);
    }

    #[test]
    fn streaming_response_keeps_accumulated_text_without_terminal_events() {
        // A response body truncated by the capture budget keeps its deltas but
        // loses every terminal event.
        let exchange = sse_exchange(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"partial "}"#,
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"answer"}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("truncated streaming exchange");

        assert_eq!(parsed.response_texts, vec!["partial answer"]);
    }

    #[test]
    fn streaming_response_recovers_text_lost_from_deltas() {
        // A terminal snapshot extends an incomplete accumulation instead of
        // replacing or duplicating it.
        let exchange = sse_exchange(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello "}"#,
            r#"{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"Hello world"}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

        assert_eq!(parsed.response_texts, vec!["Hello world"]);
    }

    #[test]
    fn streaming_response_prefers_the_provider_snapshot_when_it_diverges() {
        let exchange = sse_exchange(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"draft"}"#,
            r#"{"type":"response.output_text.done","output_index":0,"content_index":0,"text":"final"}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

        assert_eq!(parsed.response_texts, vec!["final"]);
    }

    #[test]
    fn streaming_response_keeps_reasoning_summary_and_message_order() {
        let exchange = sse_exchange(&[
            r#"{"type":"response.reasoning_summary_text.delta","output_index":0,"summary_index":0,"delta":"thinking"}"#,
            r#"{"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"answer"}"#,
            r#"{"type":"response.completed","response":{"id":"resp_1","model":"gpt-5","output":[{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}]}}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

        assert_eq!(parsed.response_texts, vec!["thinking", "answer"]);
    }

    #[test]
    fn streaming_response_keeps_parallel_message_parts_separate() {
        let exchange = sse_exchange(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":1,"delta":"second"}"#,
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"first"}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

        assert_eq!(parsed.response_texts, vec!["first", "second"]);
    }

    #[test]
    fn streaming_response_ignores_tool_call_items() {
        let exchange = sse_exchange(&[
            r#"{"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"answer"}"#,
            r#"{"type":"response.output_item.done","output_index":1,"item":{"id":"fc_1","type":"function_call","name":"read_file","arguments":"{}"}}"#,
        ]);

        let parsed = parse_openai_exchange(&exchange).expect("streaming exchange");

        assert_eq!(parsed.response_texts, vec!["answer"]);
    }

    fn sse_exchange(events: &[&str]) -> HttpExchange {
        let mut body = String::new();
        for event in events {
            body.push_str("data: ");
            body.push_str(event);
            body.push_str("\n\n");
        }
        body.push_str("data: [DONE]\n\n");
        exchange(
            "/v1/responses",
            &json!({"model": "gpt-5", "input": [{"role": "user", "content": "hi"}], "stream": true}),
            "text/event-stream",
            body.into_bytes(),
        )
    }

    fn json_exchange(path: &str, request: &Value, response: &Value) -> HttpExchange {
        exchange(
            path,
            request,
            "application/json",
            serde_json::to_vec(response).unwrap(),
        )
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
