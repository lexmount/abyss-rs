//! Responses function/custom call items and submitted outputs.

use serde_json::Value;

use crate::protocol::{
    model::tool::ParsedToolEvent,
    shared::text::{MAX_PARSE_DEPTH, json_to_text, non_empty_trimmed},
};

pub fn extract_request_tool_events(payload: &Value) -> Vec<ParsedToolEvent> {
    let mut events = Vec::new();
    collect_request_tool_events(payload, MAX_PARSE_DEPTH, &mut events);
    events
}

fn collect_request_tool_events(value: &Value, depth: usize, events: &mut Vec<ParsedToolEvent>) {
    if depth == 0 {
        return;
    }

    match value {
        Value::Object(object) => {
            if matches!(
                object.get("type").and_then(Value::as_str),
                Some("custom_tool_call_output" | "function_call_output")
            ) && let Some(output) = object
                .get("output")
                .and_then(|output| json_to_text(output, depth.saturating_sub(1)))
                .and_then(|output| non_empty_trimmed(&output).map(str::to_owned))
            {
                push_unique_tool_event(
                    events,
                    ParsedToolEvent::ToolResult {
                        call_id: optional_object_string(object, "call_id"),
                        output,
                    },
                );
            } else {
                for child in object.values() {
                    collect_request_tool_events(child, depth.saturating_sub(1), events);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_request_tool_events(item, depth.saturating_sub(1), events);
            }
        }
        _ => {}
    }
}

fn optional_object_string(object: &serde_json::Map<String, Value>, key: &str) -> Option<String> {
    object
        .get(key)
        .and_then(Value::as_str)
        .and_then(non_empty_trimmed)
        .map(str::to_owned)
}

fn push_unique_tool_event(events: &mut Vec<ParsedToolEvent>, event: ParsedToolEvent) {
    if !events.contains(&event) {
        events.push(event);
    }
}

/// The tool call a `function_call` or `custom_tool_call` item requests, once
/// its input has arrived; earlier snapshots such as `output_item.added` carry
/// none.
pub fn tool_call(item: &Value) -> Option<ParsedToolEvent> {
    if !matches!(
        item.get("type").and_then(Value::as_str),
        Some("custom_tool_call" | "function_call")
    ) {
        return None;
    }
    let input = item
        .get("input")
        .or_else(|| item.get("arguments"))
        .and_then(|input| json_to_text(input, MAX_PARSE_DEPTH))
        .and_then(|input| non_empty_trimmed(&input).map(str::to_owned))?;
    let field = |key: &str| {
        item.get(key)
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(str::to_owned)
    };
    Some(ParsedToolEvent::ToolCall {
        item_id: field("id"),
        call_id: field("call_id"),
        name: field("name"),
        input,
    })
}
