//! OpenAI-family response identity, model and client session metadata.

use http::HeaderMap;
use serde_json::Value;

use crate::protocol::shared::{http::header, json::collect_string_field, text::non_empty_trimmed};

const CODEX_TURN_METADATA: &str = "x-codex-turn-metadata";

/// The response identity where the protocol puts it: `response.id` on a
/// Responses stream event, and the top-level `id` of a whole Responses or
/// Chat Completions document, which every Chat Completions stream chunk
/// repeats.
pub fn response_id(values: &[Value]) -> Option<String> {
    values.iter().find_map(|value| {
        let id = if value.get("type").is_some() {
            value.pointer("/response/id")
        } else {
            value.get("id")
        };
        id.and_then(Value::as_str).map(str::to_owned)
    })
}

pub fn first_model(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "model"))
}

pub fn session_id(headers: &HeaderMap) -> Option<String> {
    header(headers, "session-id")
        .or_else(|| header(headers, "session_id"))
        .or_else(|| header(headers, "thread-id"))
        .map(str::to_owned)
        .or_else(|| metadata_header_value(headers, "session_id"))
        .or_else(|| metadata_header_value(headers, "thread_id"))
        .or_else(|| header(headers, "x-deepseek-harness-session-id").map(str::to_owned))
        .or_else(|| header(headers, "x-hermes-session-id").map(str::to_owned))
}

fn metadata_header_value(headers: &HeaderMap, key: &str) -> Option<String> {
    let metadata = header(headers, CODEX_TURN_METADATA)?;
    let value = serde_json::from_str::<Value>(metadata).ok()?;
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
        .map(str::to_owned)
}
