//! Shared text extraction primitives for provider protocol parsers.

use serde_json::Value;

/// Returns a trimmed string when it is not empty.
#[must_use]
pub fn non_empty_trimmed(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Extracts text from a JSON scalar/object/array with bounded recursion.
#[must_use]
pub fn json_to_text(value: &Value, depth: usize) -> Option<String> {
    if depth == 0 {
        return None;
    }

    match value {
        Value::String(text) => non_empty_trimmed(text).map(str::to_owned),
        Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(|item| json_to_text(item, depth.saturating_sub(1)))
                .collect::<Vec<_>>()
                .join("\n");
            non_empty_trimmed(&joined).map(str::to_owned)
        }
        Value::Object(object) => object
            .get("text")
            .or_else(|| object.get("content"))
            .or_else(|| object.get("input"))
            .or_else(|| object.get("output_text"))
            .and_then(|child| json_to_text(child, depth.saturating_sub(1))),
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
