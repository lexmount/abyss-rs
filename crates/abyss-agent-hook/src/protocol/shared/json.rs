//! Common bounded event-type and JSON field access.

use serde_json::Value;

use super::text::{MAX_PARSE_DEPTH, non_empty_trimmed};

pub fn collect_string_field(value: &Value, key: &str) -> Option<String> {
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

pub fn event_types(value: &Value) -> Vec<String> {
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

pub fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
}
