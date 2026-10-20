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
    // Kimi also reports a top-level cache-read alias and cache_write_tokens
    // in the details object. Prefer existing counters, including explicit zero.
    let cache_read = nested_int_field(object, "input_tokens_details", "cached_tokens")
        .or_else(|| nested_int_field(object, "prompt_tokens_details", "cached_tokens"))
        .or_else(|| int_field(object, "cached_tokens"))
        .unwrap_or(0);
    let cache_write = nested_int_field(object, "input_tokens_details", "cache_creation_tokens")
        .or_else(|| nested_int_field(object, "prompt_tokens_details", "cache_creation_tokens"))
        .or_else(|| nested_int_field(object, "input_tokens_details", "cache_write_tokens"))
        .or_else(|| nested_int_field(object, "prompt_tokens_details", "cache_write_tokens"))
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::best_usage;

    #[test]
    fn compatible_cache_fields_partition_input_without_double_counting_aliases() {
        for usage in [
            json!({
                "prompt_tokens": 100_i32, "completion_tokens": 12_i32, "cached_tokens": 60_i32,
                "prompt_tokens_details": {"cached_tokens": 60_i32, "cache_write_tokens": 30_i32}
            }),
            json!({
                "input_tokens": 100_i32, "output_tokens": 12_i32,
                "input_tokens_details": {"cached_tokens": 60_i32, "cache_write_tokens": 30_i32}
            }),
            json!({
                "prompt_tokens": 100_i32, "completion_tokens": 12_i32, "cached_tokens": 60_i32,
                "prompt_tokens_details": {"cache_write_tokens": 30_i32}
            }),
        ] {
            let usage = best_usage(&[json!({"usage": usage})]).unwrap();
            assert_eq!(usage.input_tokens, 10);
            assert_eq!(usage.cache_read_tokens, 60);
            assert_eq!(usage.cache_write_tokens, 30);
            assert_eq!(usage.output_tokens, 12);
            assert_eq!(usage.total_tokens, 112);
        }
    }

    #[test]
    fn cache_aliases_preserve_existing_precedence_including_explicit_zero() {
        let usage = best_usage(&[json!({"usage": {
            "input_tokens": 100_i32, "output_tokens": 12_i32, "cached_tokens": 60_i32,
            "input_tokens_details": {"cached_tokens": 0_i32, "cache_creation_tokens": 0_i32, "cache_write_tokens": 30_i32},
            "prompt_tokens_details": {"cached_tokens": 80_i32, "cache_creation_tokens": 20_i32, "cache_write_tokens": 10_i32}
        }})]).unwrap();
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.cache_read_tokens, 0);
        assert_eq!(usage.cache_write_tokens, 0);
        assert_eq!(usage.total_tokens, 112);
    }

    #[test]
    fn invalid_cache_fields_do_not_hide_valid_aliases_or_create_negative_input() {
        let usage = best_usage(&[json!({"usage": {
            "prompt_tokens": 10_i32, "completion_tokens": 2_i32, "cached_tokens": 30_i32,
            "prompt_tokens_details": {"cached_tokens": -1_i32, "cache_creation_tokens": "bad", "cache_write_tokens": 5_i32}
        }})]).unwrap();
        assert_eq!(usage.input_tokens, 0);
        assert_eq!(usage.cache_read_tokens, 30);
        assert_eq!(usage.cache_write_tokens, 5);
        for invalid in [json!(-1_i32), json!(null), json!("5"), json!(1.5_f64)] {
            let usage = best_usage(&[json!({"usage": {
                "prompt_tokens": 10_i32, "completion_tokens": 2_i32, "cached_tokens": invalid,
                "prompt_tokens_details": {"cache_write_tokens": invalid}
            }})])
            .unwrap();
            assert_eq!(usage.input_tokens, 10);
            assert_eq!(usage.cache_read_tokens, 0);
            assert_eq!(usage.cache_write_tokens, 0);
            assert_eq!(usage.total_tokens, 12);
        }
    }
}
