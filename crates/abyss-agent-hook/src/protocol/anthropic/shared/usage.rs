//! Anthropic token accounting and Claude Web visible-content estimates.

use serde_json::Value;

use crate::protocol::{
    model::{tool::ParsedToolEvent, usage::TokenUsage},
    shared::text::MAX_PARSE_DEPTH,
};

pub fn best_usage(values: &[Value]) -> Option<TokenUsage> {
    let mut counters = UsageCounters::default();
    for value in values {
        counters.visit(value, MAX_PARSE_DEPTH);
    }
    let usage = counters.into_usage();
    (!usage.is_empty()).then_some(usage)
}

/// Cumulative counters may be corrected by later Messages events. Keep the
/// latest reported value of each field, including zero, and retain omitted ones.
/// Partition compatible input totals only after all partial updates are merged.
#[derive(Default)]
struct UsageCounters {
    input: Option<i64>,
    output: Option<i64>,
    native_cache_read: Option<i64>,
    native_cache_write: Option<i64>,
    detail_cache_read: Option<i64>,
    detail_cache_write: Option<i64>,
    reasoning: Option<i64>,
}

impl UsageCounters {
    fn visit(&mut self, value: &Value, depth: usize) {
        if depth == 0 {
            return;
        }
        match value {
            Value::Object(object) => {
                self.apply(object);
                for child in object.values() {
                    self.visit(child, depth.saturating_sub(1));
                }
            }
            Value::Array(items) => {
                for item in items {
                    self.visit(item, depth.saturating_sub(1));
                }
            }
            _ => {}
        }
    }

    fn apply(&mut self, object: &serde_json::Map<String, Value>) {
        self.input = int_field(object, "input_tokens").or(self.input);
        self.output = int_field(object, "output_tokens").or(self.output);
        self.native_cache_read =
            int_field(object, "cache_read_input_tokens").or(self.native_cache_read);
        self.native_cache_write =
            int_field(object, "cache_creation_input_tokens").or(self.native_cache_write);
        self.detail_cache_read = nested_int_field(object, "input_tokens_details", "cached_tokens")
            .or(self.detail_cache_read);
        self.detail_cache_write =
            nested_int_field(object, "input_tokens_details", "cache_creation_tokens")
                .or(self.detail_cache_write);
        self.reasoning = nested_int_field(object, "output_tokens_details", "thinking_tokens")
            .or_else(|| int_field(object, "thinking_tokens"))
            .or_else(|| int_field(object, "reasoning_tokens"))
            .or(self.reasoning);
    }

    fn into_usage(self) -> TokenUsage {
        // Native Messages keeps cache counters outside input_tokens, whereas
        // compatible OpenAI-style details are included in the input total.
        let detail_cache_read = if self.native_cache_read.is_none() {
            self.detail_cache_read.unwrap_or(0)
        } else {
            0
        };
        let detail_cache_write = if self.native_cache_write.is_none() {
            self.detail_cache_write.unwrap_or(0)
        } else {
            0
        };
        TokenUsage::from_parts(
            self.input
                .unwrap_or(0)
                .saturating_sub(detail_cache_read)
                .saturating_sub(detail_cache_write)
                .max(0),
            self.native_cache_read.unwrap_or(detail_cache_read),
            self.native_cache_write.unwrap_or(detail_cache_write),
            self.output.unwrap_or(0),
            self.reasoning.unwrap_or(0),
        )
    }
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
    fn final_usage_corrects_provisional_input_and_cache_counts() {
        let usage = best_usage(&[
            json!({"type":"message_start","message":{"usage":{
                "input_tokens":4868_i32,"output_tokens":1_i32,
                "cache_read_input_tokens":0_i32,"cache_creation_input_tokens":30_i32
            }}}),
            json!({"type":"message_delta","usage":{
                "input_tokens":475_i32,"output_tokens":91_i32,
                "cache_read_input_tokens":5376_i32,"cache_creation_input_tokens":0_i32
            }}),
        ])
        .unwrap();
        assert_eq!(usage.input_tokens, 475);
        assert_eq!(usage.cache_read_tokens, 5376);
        assert_eq!(usage.cache_write_tokens, 0);
        assert_eq!(usage.output_tokens, 91);
        assert_eq!(usage.total_tokens, 5942);
    }

    #[test]
    fn partial_usage_preserves_omitted_counters_and_accepts_explicit_zero() {
        let usage = best_usage(&[
            json!({"message":{"usage":{
                "input_tokens":5_i32,"cache_read_input_tokens":60_i32,
                "cache_creation_input_tokens":30_i32,"output_tokens":1_i32,
                "output_tokens_details":{"thinking_tokens":2_i32}
            }}}),
            json!({"usage":{"output_tokens":12_i32}}),
            json!({"usage":{"input_tokens":null,"cache_read_input_tokens":-1_i32,
                "cache_creation_input_tokens":"bad","output_tokens_details":{"thinking_tokens":0_i32}}}),
        ])
        .unwrap();
        assert_eq!(usage.input_tokens, 5);
        assert_eq!(usage.cache_read_tokens, 60);
        assert_eq!(usage.cache_write_tokens, 30);
        assert_eq!(usage.output_tokens, 12);
        assert_eq!(usage.reasoning_tokens, 0);
        assert_eq!(usage.total_tokens, 107);
    }

    #[test]
    fn input_details_are_partitioned_after_merging_partial_usage() {
        let usage = best_usage(&[
            json!({"usage":{"input_tokens":100_i32,"input_tokens_details":{"cached_tokens":60_i32}}}),
            json!({"usage":{"input_tokens_details":{"cache_creation_tokens":30_i32},"output_tokens":12_i32}}),
        ])
        .unwrap();
        assert_eq!(usage.input_tokens, 10);
        assert_eq!(usage.cache_read_tokens, 60);
        assert_eq!(usage.cache_write_tokens, 30);
        assert_eq!(usage.total_tokens, 112);
    }
}
