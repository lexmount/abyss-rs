//! Anthropic model metadata.

use serde_json::Value;

use crate::protocol::shared::json::collect_string_field;

pub fn first_model(values: &[Value]) -> Option<String> {
    values
        .iter()
        .find_map(|value| collect_string_field(value, "model"))
}
