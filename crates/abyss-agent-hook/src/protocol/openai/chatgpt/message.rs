//! Message visibility and the parts of a delta document needed for display.

use abyss_plugin_protocol::event::{ConversationEntry, EntryRole};
use serde_json::Value;

use crate::protocol::model::conversation::ConversationProjection;

pub(super) fn entry(message: &Value, role: EntryRole) -> Option<ConversationEntry> {
    let expected = match role {
        EntryRole::User => "user",
        EntryRole::Assistant => "assistant",
        _ => return None,
    };
    if message.pointer("/author/role")?.as_str()? != expected
        || message
            .pointer("/metadata/is_visually_hidden_from_conversation")
            .and_then(Value::as_bool)
            == Some(true)
        || message
            .get("recipient")
            .and_then(Value::as_str)
            .is_some_and(|r| r != "all")
        || message
            .get("channel")
            .and_then(Value::as_str)
            .is_some_and(|c| c != "final")
        || !matches!(
            message.pointer("/content/content_type")?.as_str(),
            Some("text" | "multimodal_text")
        )
    {
        return None;
    }
    let parts = message.pointer("/content/parts")?.as_array()?;
    let text: String = parts
        .iter()
        .filter_map(|v| {
            v.as_str().or_else(|| {
                (v.get("content_type")?.as_str()? == "text")
                    .then(|| v.get("text")?.as_str())
                    .flatten()
            })
        })
        .collect();
    if text.trim().is_empty() {
        return None;
    }
    let mut entry = ConversationProjection::text(role, &text);
    entry.item_id = ConversationProjection::field(message, "id");
    Some(entry)
}

fn projected(path: &str) -> bool {
    matches!(
        path,
        "" | "/message"
            | "/message/id"
            | "/message/channel"
            | "/message/recipient"
            | "/message/author"
            | "/message/author/role"
            | "/message/content"
            | "/message/content/content_type"
            | "/message/metadata"
            | "/message/metadata/is_visually_hidden_from_conversation"
            | "/message/metadata/model_slug"
            | "/message/content/parts"
    ) || path.starts_with("/message/content/parts/")
}

/// Apply one absolute operation. Metadata outside the display projection never alters text.
pub(super) fn apply(root: &mut Value, path: &str, op: &str, value: &Value) -> bool {
    if !projected(path) {
        return true;
    }
    if path.is_empty() {
        return match op {
            "add" | "replace" => {
                root.clone_from(value);
                true
            }
            "remove" => {
                *root = Value::Null;
                true
            }
            _ => false,
        };
    }
    let Some((parent, key)) = path.rsplit_once('/') else {
        return false;
    };
    let Some(parent) = root.pointer_mut(parent) else {
        return false;
    };
    let target = match parent {
        Value::Object(object) => match op {
            "add" | "replace" => {
                object.insert(key.to_owned(), value.clone());
                return true;
            }
            "remove" => {
                object.remove(key);
                return true;
            }
            _ => object.get_mut(key),
        },
        Value::Array(array) => {
            if op == "add" && key == "-" {
                array.push(value.clone());
                return true;
            }
            let Ok(index) = key.parse::<usize>() else {
                return false;
            };
            match op {
                "add" if index <= array.len() => {
                    array.insert(index, value.clone());
                    return true;
                }
                "remove" if index < array.len() => {
                    array.remove(index);
                    return true;
                }
                "replace" if index < array.len() => {
                    array[index].clone_from(value);
                    return true;
                }
                _ => array.get_mut(index),
            }
        }
        _ => None,
    };
    match (target, op, value) {
        (Some(Value::String(text)), "append", Value::String(delta)) => text.push_str(delta),
        (Some(Value::Object(fields)), "append", Value::Object(delta)) => {
            fields.extend(delta.clone());
        }
        (Some(Value::Array(items)), "append", Value::Array(delta)) => {
            items.extend_from_slice(delta);
        }
        (Some(Value::Array(items)), "truncate", Value::Number(n)) => {
            let Some(len) = n.as_u64().and_then(|n| usize::try_from(n).ok()) else {
                return false;
            };
            items.truncate(len);
        }
        _ => return false,
    }
    true
}
