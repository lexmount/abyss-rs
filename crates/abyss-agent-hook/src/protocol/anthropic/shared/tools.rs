//! Anthropic tool-result content shared by Messages and Claude Web.

use serde_json::Value;

use crate::protocol::shared::text::{MAX_PARSE_DEPTH, json_to_text};

/// The text of a `tool_result` block's `content`.
pub fn tool_result_output(content: &Value) -> String {
    match content {
        Value::String(text) => text.clone(),
        Value::Array(items) => items
            .iter()
            .filter_map(tool_result_part)
            .collect::<Vec<_>>()
            .join("\n"),
        Value::Object(_) => tool_result_part(content).unwrap_or_default(),
        _ => String::new(),
    }
}

fn tool_result_part(value: &Value) -> Option<String> {
    let object = value.as_object()?;
    if object.get("type").and_then(Value::as_str) == Some("image") {
        let media_type = object
            .get("source")
            .and_then(Value::as_object)
            .and_then(|source| source.get("media_type"))
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        return Some(format!("[image attachment: {media_type}]"));
    }
    // Structured tool results are model-visible audit content just like text
    // results. Preserve their complete captured JSON when no text projection
    // exists; the event content mode still redacts this output unless the
    // configured audit policy explicitly allows plaintext retention. The HTTP
    // capture boundary provides the payload size limit.
    json_to_text(value, MAX_PARSE_DEPTH).or_else(|| serde_json::to_string(value).ok())
}
