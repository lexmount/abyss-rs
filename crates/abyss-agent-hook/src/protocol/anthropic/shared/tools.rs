//! Anthropic content-block tool calls and results shared by Messages and Claude Web.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::protocol::shared::json::string_field;
use crate::protocol::{
    model::tool::ParsedToolEvent,
    shared::text::{MAX_PARSE_DEPTH, json_to_text, non_empty_trimmed},
};

pub fn extract_request_tool_events(payload: &Value) -> Vec<ParsedToolEvent> {
    let mut events = Vec::new();
    let latest_user_content = payload
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|messages| {
            messages
                .iter()
                .rev()
                .find(|message| string_field(message, "role") == Some("user"))
        })
        .and_then(|message| message.get("content"));
    if let Some(content) = latest_user_content.or_else(|| payload.get("input")) {
        collect_request_tool_events(content, MAX_PARSE_DEPTH, &mut events);
    }
    events
}

fn collect_request_tool_events(value: &Value, depth: usize, events: &mut Vec<ParsedToolEvent>) {
    if depth == 0 {
        return;
    }
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("tool_result") {
                let output = object
                    .get("content")
                    .map(tool_result_output)
                    .unwrap_or_default();
                let event = ParsedToolEvent::ToolResult {
                    call_id: optional_object_string(object, "tool_use_id"),
                    output,
                };
                push_unique_tool_event(events, event);
                return;
            }
            for child in object.values() {
                collect_request_tool_events(child, depth.saturating_sub(1), events);
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

fn tool_result_output(content: &Value) -> String {
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

pub fn extract_response_tool_events(values: &[Value]) -> Vec<ParsedToolEvent> {
    let streaming = streaming_tool_events(values);
    if !streaming.is_empty() {
        return streaming;
    }
    let mut events = Vec::new();
    for value in values {
        collect_response_tool_events(value, MAX_PARSE_DEPTH, &mut events);
    }
    events
}

#[derive(Default)]
struct StreamingToolCall {
    id: Option<String>,
    name: Option<String>,
    initial_input: Option<Value>,
    input_json: String,
}

enum StreamingToolBlock {
    Call(StreamingToolCall),
    Result(ParsedToolEvent),
}

fn streaming_tool_events(values: &[Value]) -> Vec<ParsedToolEvent> {
    let mut blocks = BTreeMap::<u64, StreamingToolBlock>::new();
    for value in values {
        let index = value.get("index").and_then(Value::as_u64).unwrap_or(0);
        match value.get("type").and_then(Value::as_str) {
            Some("content_block_start") => {
                let Some(block) = value.get("content_block").and_then(Value::as_object) else {
                    continue;
                };
                match block.get("type").and_then(Value::as_str) {
                    Some("tool_use") => {
                        blocks.insert(
                            index,
                            StreamingToolBlock::Call(StreamingToolCall {
                                id: optional_object_string(block, "id"),
                                name: optional_object_string(block, "name"),
                                initial_input: block.get("input").cloned(),
                                input_json: String::new(),
                            }),
                        );
                    }
                    Some("tool_result") => {
                        let output = block
                            .get("content")
                            .map(tool_result_output)
                            .unwrap_or_default();
                        blocks.insert(
                            index,
                            StreamingToolBlock::Result(ParsedToolEvent::ToolResult {
                                call_id: optional_object_string(block, "tool_use_id"),
                                output,
                            }),
                        );
                    }
                    _ => {}
                }
            }
            Some("content_block_delta") => {
                let Some(delta) = value.get("delta").and_then(Value::as_object) else {
                    continue;
                };
                if delta.get("type").and_then(Value::as_str) != Some("input_json_delta") {
                    continue;
                }
                if let Some(fragment) = delta.get("partial_json").and_then(Value::as_str)
                    && let Some(StreamingToolBlock::Call(call)) = blocks.get_mut(&index)
                {
                    call.input_json.push_str(fragment);
                }
            }
            _ => {}
        }
    }

    blocks
        .into_values()
        .map(|block| match block {
            StreamingToolBlock::Call(call) => {
                let input = if non_empty_trimmed(&call.input_json).is_some() {
                    canonical_tool_input(&Value::String(call.input_json))
                } else {
                    call.initial_input
                        .as_ref()
                        .map_or_else(|| "{}".to_owned(), canonical_tool_input)
                };
                ParsedToolEvent::ToolCall {
                    item_id: call.id.clone(),
                    call_id: call.id,
                    name: call.name,
                    input,
                }
            }
            StreamingToolBlock::Result(result) => result,
        })
        .collect()
}

fn collect_response_tool_events(value: &Value, depth: usize, events: &mut Vec<ParsedToolEvent>) {
    if depth == 0 {
        return;
    }
    match value {
        Value::Object(object) => {
            if object.get("type").and_then(Value::as_str) == Some("tool_result") {
                let output = object
                    .get("content")
                    .map(tool_result_output)
                    .unwrap_or_default();
                push_unique_tool_event(
                    events,
                    ParsedToolEvent::ToolResult {
                        call_id: optional_object_string(object, "tool_use_id"),
                        output,
                    },
                );
                return;
            }
            if object.get("type").and_then(Value::as_str) == Some("tool_use") {
                let id = optional_object_string(object, "id");
                push_unique_tool_event(
                    events,
                    ParsedToolEvent::ToolCall {
                        item_id: id.clone(),
                        call_id: id,
                        name: optional_object_string(object, "name"),
                        input: object
                            .get("input")
                            .map_or_else(|| "{}".to_owned(), canonical_tool_input),
                    },
                );
                return;
            }
            for child in object.values() {
                collect_response_tool_events(child, depth.saturating_sub(1), events);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_response_tool_events(item, depth.saturating_sub(1), events);
            }
        }
        _ => {}
    }
}

fn canonical_tool_input(input: &Value) -> String {
    if let Some(input) = input.as_str() {
        return serde_json::from_str::<Value>(input)
            .ok()
            .and_then(|value| serde_json::to_string(&value).ok())
            .unwrap_or_else(|| input.to_owned());
    }
    serde_json::to_string(input).unwrap_or_default()
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
