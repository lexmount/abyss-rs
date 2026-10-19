//! Claude Web request turn and uploaded-file references.

use serde_json::Value;

use crate::protocol::shared::text::non_empty_trimmed;

pub(super) struct TurnMessageUuids {
    pub(super) human: Option<String>,
    pub(super) assistant: Option<String>,
}

pub(super) fn turn_message_uuids(payload: &Value) -> TurnMessageUuids {
    let turn_message_uuids = payload.get("turn_message_uuids").and_then(Value::as_object);
    TurnMessageUuids {
        human: turn_message_uuids
            .and_then(|object| object.get("human_message_uuid"))
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(str::to_owned),
        assistant: turn_message_uuids
            .and_then(|object| object.get("assistant_message_uuid"))
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(str::to_owned),
    }
}

pub(super) fn claude_web_file_uuids(payload: &Value) -> Vec<String> {
    let mut file_uuids = Vec::new();
    let Some(files) = payload.get("files").and_then(Value::as_array) else {
        return file_uuids;
    };
    for file_uuid in files {
        let Some(file_uuid) = file_uuid.as_str().and_then(non_empty_trimmed) else {
            continue;
        };
        if !file_uuids.iter().any(|existing| existing == file_uuid) {
            file_uuids.push(file_uuid.to_owned());
        }
    }
    file_uuids
}
