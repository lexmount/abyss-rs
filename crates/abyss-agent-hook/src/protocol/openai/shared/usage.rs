//! OpenAI-family token accounting, including compatible gateways.

use serde_json::Value;

use crate::protocol::{model::usage::TokenUsage, shared::text::MAX_PARSE_DEPTH};

pub fn best_usage(values: &[Value]) -> Option<TokenUsage> {
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
        .or_else(|| nested_int_field(object, "completion_tokens_details", "reasoning_tokens"))
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
