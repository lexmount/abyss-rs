//! Anthropic token accounting and Claude Web visible-content estimates.

use serde_json::Value;

use crate::protocol::{
    model::{tool::ParsedToolEvent, usage::TokenUsage},
    shared::text::MAX_PARSE_DEPTH,
};

pub fn best_usage(values: &[Value]) -> Option<TokenUsage> {
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

pub fn estimated_visible_usage(
    request_texts: &[String],
    request_tool_events: &[ParsedToolEvent],
    response_texts: &[String],
    response_tool_events: &[ParsedToolEvent],
) -> TokenUsage {
    let input_tokens = estimate_visible_tokens(request_texts, request_tool_events);
    let output_tokens = estimate_visible_tokens(response_texts, response_tool_events);
    TokenUsage::from_parts(input_tokens, 0, 0, output_tokens, 0)
}

fn estimate_visible_tokens(texts: &[String], tool_events: &[ParsedToolEvent]) -> i64 {
    let text_byte_count = texts
        .iter()
        .map(|text| text.trim().len())
        .fold(0_usize, usize::saturating_add);
    let tool_byte_count = tool_events
        .iter()
        .map(|event| match event {
            ParsedToolEvent::ToolCall { name, input, .. } => name
                .as_deref()
                .map_or(0, str::len)
                .saturating_add(input.trim().len()),
            ParsedToolEvent::ToolResult { output, .. } => output.trim().len(),
        })
        .fold(0_usize, usize::saturating_add);
    let byte_count = text_byte_count.saturating_add(tool_byte_count);
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
