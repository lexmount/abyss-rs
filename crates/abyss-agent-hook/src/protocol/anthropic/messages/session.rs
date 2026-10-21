//! Messages session correlation from client headers and request metadata.

use http::HeaderMap;
use serde_json::Value;

use super::model::AnthropicSessionIdSource;
use crate::protocol::shared::{http::header, json::collect_string_field, text::non_empty_trimmed};

pub(super) struct ResolvedAnthropicSessionId {
    pub(super) id: String,
    pub(super) source: AnthropicSessionIdSource,
}

pub(super) fn anthropic_session_id(
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
        .or_else(|| header(headers, "x-deepseek-harness-session-id"))
        .or_else(|| header(headers, "x-hermes-session-id"))
        .map(str::to_owned)
        .or_else(|| metadata_session_id(payload))
        .or_else(|| collect_string_field(payload, "session_id"))
        .or_else(|| header(headers, "session-id").map(str::to_owned))
        .or_else(|| header(headers, "session_id").map(str::to_owned))
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
