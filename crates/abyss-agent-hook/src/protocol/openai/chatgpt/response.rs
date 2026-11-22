//! Assemble v1 delta envelopes into independent message documents by stream slot.

use super::message;
use crate::protocol::{
    model::{
        conversation::ConversationProjection,
        response::{ResponseContent, ResponseInput},
    },
    shared::json::string_field,
};
use abyss_plugin_protocol::event::EntryRole;
use serde_json::Value;
use std::collections::BTreeMap;

struct Stream<'a> {
    // Compression reuses the preceding envelope's coordinates, including across slot changes.
    slot: u64,
    path: &'a str,
    operation: &'a str,
    documents: BTreeMap<u64, Value>,
    session: Option<&'a str>,
    terminal: bool,
    partial: bool,
}

impl<'a> Stream<'a> {
    fn observe(&mut self, frame: &'a Value) {
        self.session = self
            .session
            .or_else(|| string_field(frame, "conversation_id"))
            .or_else(|| {
                frame
                    .get("v")
                    .and_then(|v| string_field(v, "conversation_id"))
            });
        if let Some(kind) = frame.get("type").and_then(Value::as_str) {
            self.terminal |= kind == "message_stream_complete";
            return;
        }
        if frame.get("message").is_some() {
            self.documents.insert(self.slot, frame.clone());
            return;
        }
        if frame.get("v").is_none() && frame.get("o").and_then(Value::as_str) != Some("remove") {
            return;
        }
        self.slot = frame.get("c").and_then(Value::as_u64).unwrap_or(self.slot);
        self.path = frame.get("p").and_then(Value::as_str).unwrap_or(self.path);
        self.operation = frame
            .get("o")
            .and_then(Value::as_str)
            .unwrap_or(self.operation);
        let root = self.documents.entry(self.slot).or_default();
        if self.operation == "patch" {
            let Some(operations) = frame["v"].as_array() else {
                self.partial = true;
                return;
            };
            for op in operations {
                let (Some(path), Some(operation)) = (op["p"].as_str(), op["o"].as_str()) else {
                    self.partial = true;
                    continue;
                };
                if self.path.is_empty() {
                    self.partial |= !message::apply(root, path, operation, &op["v"]);
                } else {
                    self.partial |=
                        !message::apply(root, &format!("{}{path}", self.path), operation, &op["v"]);
                }
            }
        } else {
            self.partial |= !message::apply(root, self.path, self.operation, &frame["v"]);
        }
    }
}

pub(super) fn assemble(input: &ResponseInput<'_>) -> ResponseContent {
    let mut stream = Stream {
        slot: 0,
        path: "",
        operation: "add",
        documents: BTreeMap::new(),
        session: None,
        terminal: false,
        partial: false,
    };
    for frame in input.values {
        stream.observe(frame);
    }
    let mut entries = Vec::new();
    let mut model = None;
    for doc in stream.documents.into_values() {
        if let Some(msg) = doc.get("message")
            && let Some(entry) = message::entry(msg, EntryRole::Assistant)
        {
            if let Some(slug) = msg.pointer("/metadata/model_slug").and_then(Value::as_str) {
                model = Some(slug.to_owned());
            }
            entries.push(entry);
        }
    }
    let response_id = entries.last().and_then(|entry| entry.item_id.clone());
    let partial = stream.partial
        || input.decode_failed
        || input.assembly_overflowed
        || (input.capture_truncated && !stream.terminal);
    let completeness =
        ConversationProjection::completeness(!entries.is_empty() || stream.terminal, partial);
    ResponseContent {
        has_content: !entries.is_empty(),
        conversation: ConversationProjection::from_entries(entries, completeness),
        model,
        session_id: stream.session.map(str::to_owned),
        response_id,
        usage: None,
        event_types: input
            .values
            .iter()
            .filter_map(|v| string_field(v, "type").map(str::to_owned))
            .collect(),
    }
}
