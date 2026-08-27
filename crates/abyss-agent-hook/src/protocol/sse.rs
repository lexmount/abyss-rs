//! Provider-neutral Server-Sent Events framing and JSON decoding.

use serde_json::Value;

/// Parses JSON payloads from a server-sent events byte stream.
///
/// Each event may contain multiple `data:` lines. Stream sentinels such as
/// `[DONE]` and malformed application payloads are ignored.
#[must_use]
pub fn parse_sse_json_values(bytes: &[u8]) -> Vec<Value> {
    let text = String::from_utf8_lossy(bytes);
    let mut values = Vec::new();
    let mut event_data = Vec::new();

    for line in text.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(data) = line.strip_prefix("data:") {
            let data = data.trim();
            if data != "[DONE]" {
                event_data.push(data.to_owned());
            }
            continue;
        }
        if line.is_empty() && !event_data.is_empty() {
            push_event(&mut values, &event_data.join("\n"));
            event_data.clear();
        }
    }

    if !event_data.is_empty() {
        push_event(&mut values, &event_data.join("\n"));
    }
    values
}

fn push_event(values: &mut Vec<Value>, data: &str) {
    if let Ok(value) = serde_json::from_str::<Value>(data) {
        values.push(value);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_sse_json_values;

    #[test]
    fn parses_json_data_events() {
        let values = parse_sse_json_values(
            b"event: message\r\ndata: {\"type\":\"content_block_delta\"}\r\n\r\n",
        );

        assert_eq!(values.len(), 1);
        assert_eq!(values[0]["type"], "content_block_delta");
    }
}
