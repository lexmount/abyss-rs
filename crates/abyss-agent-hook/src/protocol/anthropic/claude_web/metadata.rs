//! Claude Web request turn and uploaded-file references.

use serde_json::Value;

use crate::protocol::shared::text::non_empty_trimmed;

/// The assistant message UUID the request assigns to its turn.
pub(super) fn assistant_message_uuid(payload: &Value) -> Option<String> {
    payload
        .get("turn_message_uuids")?
        .get("assistant_message_uuid")?
        .as_str()
        .and_then(non_empty_trimmed)
        .map(str::to_owned)
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
