//! Shared text extraction primitives for provider protocol parsers.

use serde_json::Value;

/// Recursion bound for walking provider JSON documents.
pub const MAX_PARSE_DEPTH: usize = 12;

/// Returns a trimmed string when it is not empty.
#[must_use]
pub fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Extracts text from a JSON scalar/object/array with bounded recursion.
#[must_use]
pub fn json_to_text(value: &Value, depth: usize) -> Option<String> {
    visible_text(value, depth, |_| false)
}

/// Like [`json_to_text`], except that an object whose `type` satisfies
/// `is_tool` contributes no text.
#[must_use]
pub fn visible_text(value: &Value, depth: usize, is_tool: fn(&str) -> bool) -> Option<String> {
    if depth == 0 {
        return None;
    }

    match value {
        Value::String(text) => non_empty_trimmed(text).map(str::to_owned),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(|item| visible_text(item, depth.saturating_sub(1), is_tool))
                .collect::<Vec<_>>()
                .join("\n");
            non_empty_trimmed(&joined).map(str::to_owned)
        }
        Value::Object(object) => {
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(is_tool)
            {
                return None;
            }
            object
                .get("text")
                .or_else(|| object.get("content"))
                .or_else(|| object.get("input"))
                .or_else(|| object.get("output_text"))
                .and_then(|child| visible_text(child, depth.saturating_sub(1), is_tool))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::json_to_text;

    #[test]
    fn extracts_nested_content() {
        assert_eq!(
            json_to_text(&json!([{ "type": "input_text", "text": "hello" }]), 4),
            Some("hello".to_owned())
        );
    }
}
