//! Anthropic model and stop-reason metadata.

use serde_json::Value;

use crate::protocol::shared::json::collect_string_field;

pub fn first_model(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "model"))
}

pub fn first_stop_reason(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "stop_reason"))
}
