//! OpenAI Responses and Chat Completions conversation projection.
//!
//! Every request item, content part, and response output item is classified
//! once by the block-to-role table in [`OpenAiContent::item_entries`] and
//! [`OutputSlot::entries`]: one conversation entry per item or part, in
//! provider order. Responses replay streamed deltas onto per-output slots and
//! reconcile them with provider snapshots, so an answer republished by several
//! terminal events is reported once. Every entry of a Responses input or
//! output item carries the item's `id`; Chat Completions entries carry none.
//!
//! Both dialects are recognized by the fields a body carries, not by its path.
//! This module holds what they share: the message and part table, the request
//! and response entry points, and the output slots. [`responses`] holds the
//! Responses items and stream events, and [`chat`] the Chat Completions tool
//! messages, message-level calls, and choices.

mod chat;
mod responses;

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{
    ContentCompleteness, Conversation, ConversationEntry, EntryRole,
};
use serde_json::Value;

use crate::protocol::model::{
    conversation::ConversationProjection,
    text::{MAX_PARSE_DEPTH, json_to_text, non_empty_trimmed},
};

type Projection = ConversationProjection;

/// OpenAI-specific item and message rules.
pub struct OpenAiContent;

impl OpenAiContent {
    /// Appends the entries of one request item, by the block-to-role table:
    /// messages contribute one entry per content part, `reasoning` one entry,
    /// every `*_call` a tool call, every `*_output` a tool result, and any
    /// other item one `unknown` entry when it carries text.
    fn item_entries(item: &Value, default_role: EntryRole, entries: &mut Vec<ConversationEntry>) {
        if let Value::String(text) = item {
            entries.push(Projection::text(default_role, text));
            return;
        }
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => entries.push(Projection::text(
                EntryRole::Reasoning,
                &responses::reasoning_text(item).unwrap_or_default(),
            )),
            Some(kind) if kind.ends_with("_call") => entries.push(responses::call_entry(item)),
            Some(kind) if kind.ends_with("_output") => {
                entries.push(responses::output_entry(item));
            }
            Some("message") => Self::message_entries(item, default_role, entries),
            None if item.get("role").is_some() || item.get("content").is_some() => {
                Self::message_entries(item, default_role, entries);
            }
            _ => entries.extend(Projection::unknown(item)),
        }
    }

    /// Entries of one Responses message item or Chat Completions message.
    fn message_entries(
        item: &Value,
        default_role: EntryRole,
        entries: &mut Vec<ConversationEntry>,
    ) {
        let role = item
            .get("role")
            .and_then(Value::as_str)
            .map_or(default_role, Projection::role);
        if role == EntryRole::ToolResult {
            entries.push(chat::tool_message_entry(item));
            return;
        }
        match item.get("content") {
            Some(Value::String(text)) => entries.push(Projection::text(role, text)),
            Some(Value::Array(parts)) => {
                entries.extend(parts.iter().filter_map(|part| part_entry(part, role)));
            }
            _ => {}
        }
        chat::message_extra_entries(item, entries);
    }
}

/// The entry of one message content part.
fn part_entry(part: &Value, role: EntryRole) -> Option<ConversationEntry> {
    if let Value::String(text) = part {
        return Some(Projection::text(role, text));
    }
    match part.get("type").and_then(Value::as_str) {
        Some("input_text" | "output_text" | "text" | "summary_text") => Some(Projection::text(
            role,
            &Projection::field(part, "text").unwrap_or_default(),
        )),
        Some("refusal") => Some(Projection::text(
            EntryRole::Assistant,
            &Projection::field(part, "refusal").unwrap_or_default(),
        )),
        _ => Projection::unknown(part),
    }
}

/// A tool output: a string as sent, otherwise its text parts or its JSON.
fn output_text(output: &Value) -> String {
    match output {
        Value::String(text) => text.clone(),
        value => {
            json_to_text(value, MAX_PARSE_DEPTH).unwrap_or_else(|| Projection::verbatim(value))
        }
    }
}

/// Request-side entries.
pub struct OpenAiRequest {
    /// Whether the request carried a message-bearing field: `instructions`, a
    /// non-empty `input` or `messages`, or a non-blank `prompt`.
    carries_messages: bool,
    /// One entry per item or part: `instructions`, `input`, `messages`, then
    /// `prompt`. Entries of a Responses item carry its `id`.
    entries: Vec<ConversationEntry>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl OpenAiRequest {
    /// Projects one request body; `None` means it could not be decoded.
    #[must_use]
    pub fn parse(payload: Option<&Value>, truncated: bool) -> Self {
        let mut request = Self {
            carries_messages: false,
            entries: Vec::new(),
            completeness: Projection::completeness(payload.is_some(), truncated),
        };
        let Some(payload) = payload else {
            return request;
        };
        responses::push_request(&mut request, payload);
        chat::push_request(&mut request, payload);
        if let Some(prompt) = payload
            .get("prompt")
            .and_then(Value::as_str)
            .filter(|prompt| non_empty_trimmed(prompt).is_some())
        {
            request.carries_messages = true;
            request
                .entries
                .push(Projection::text(EntryRole::User, prompt));
        }
        request
    }

    /// Whether the request carried no message-bearing field.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        !self.carries_messages
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        Projection::from_entries(self.entries.clone(), self.completeness)
    }
}

/// A tool call under assembly.
#[derive(Default)]
struct CallSlot {
    call_id: Option<String>,
    name: Option<String>,
    /// Arguments or input from the latest snapshot that carried them.
    input: String,
    /// Arguments or input accumulated from streamed deltas.
    streamed: String,
}

impl CallSlot {
    fn entry(&self) -> ConversationEntry {
        Projection::tool_call(
            self.call_id.clone(),
            self.name.clone(),
            if self.input.is_empty() {
                self.streamed.clone()
            } else {
                self.input.clone()
            },
        )
    }
}

/// One content part of a message.
enum Part {
    /// Text in the message's role.
    Text(String),
    /// A refusal, always the assistant's.
    Refusal(String),
}

/// What one output item or chat choice holds, by the block-to-role table.
enum SlotBody {
    /// A message item or chat choice: its parts by content index, then the
    /// Chat Completions tool calls by their index.
    Message {
        parts: BTreeMap<u64, Part>,
        calls: BTreeMap<u64, CallSlot>,
    },
    /// A `reasoning` item: its summary, or else content, parts by index.
    Reasoning { parts: BTreeMap<u64, String> },
    /// A `*_call` item.
    ToolCall(CallSlot),
    /// A `*_output` item.
    ToolResult {
        call_id: Option<String>,
        output: String,
    },
    /// Any other item, with its text when it carries some.
    Other(Option<String>),
}

impl SlotBody {
    const fn message() -> Self {
        Self::Message {
            parts: BTreeMap::new(),
            calls: BTreeMap::new(),
        }
    }

    const fn reasoning() -> Self {
        Self::Reasoning {
            parts: BTreeMap::new(),
        }
    }

    /// The empty body of an item of `item_type`.
    fn for_item(item_type: Option<&str>) -> Self {
        match item_type {
            Some("reasoning") => Self::reasoning(),
            Some(kind) if kind.ends_with("_call") => Self::ToolCall(CallSlot::default()),
            Some(kind) if kind.ends_with("_output") => Self::ToolResult {
                call_id: None,
                output: String::new(),
            },
            Some("message") | None => Self::message(),
            Some(_) => Self::Other(None),
        }
    }
}

/// One output item or chat choice under assembly.
struct OutputSlot {
    /// The Responses output item's `id`; chat choices have none.
    item_id: Option<String>,
    /// Role declared by the item, or assistant.
    role: EntryRole,
    /// What the item holds.
    body: SlotBody,
}

impl OutputSlot {
    const fn new(body: SlotBody) -> Self {
        Self {
            item_id: None,
            role: EntryRole::Assistant,
            body,
        }
    }

    /// The text of a message or reasoning part, created empty when absent;
    /// none for other items and for a refusal part.
    fn text_part(&mut self, index: u64) -> Option<&mut String> {
        match &mut self.body {
            SlotBody::Message { parts, .. } => {
                match parts
                    .entry(index)
                    .or_insert_with(|| Part::Text(String::new()))
                {
                    Part::Text(text) => Some(text),
                    Part::Refusal(_) => None,
                }
            }
            SlotBody::Reasoning { parts } => Some(parts.entry(index).or_default()),
            _ => None,
        }
    }

    /// Applies one authoritative snapshot to a part.
    ///
    /// A snapshot that extends the accumulated text only contributes the
    /// missing suffix, an equal one changes nothing, and a diverging one
    /// replaces it because the provider, not the accumulation, is authoritative.
    fn reconcile(&mut self, index: u64, authoritative: &str) {
        if authoritative.is_empty() {
            return;
        }
        let Some(part) = self.text_part(index) else {
            return;
        };
        if let Some(suffix) = authoritative.strip_prefix(part.as_str()) {
            part.push_str(suffix);
        } else {
            authoritative.clone_into(part);
        }
    }

    /// Reconciles the body and role with one item snapshot. A snapshot of
    /// another kind than the body was started as replaces the body.
    fn reconcile_item(&mut self, item: &Value) {
        let body = SlotBody::for_item(item.get("type").and_then(Value::as_str));
        if std::mem::discriminant(&body) != std::mem::discriminant(&self.body) {
            self.body = body;
        }
        self.role = item
            .get("role")
            .and_then(Value::as_str)
            .map_or(EntryRole::Assistant, Projection::role);
        match &mut self.body {
            SlotBody::Message { calls, .. } => {
                chat::reconcile_calls(calls, item);
                self.reconcile_content(item);
            }
            SlotBody::Reasoning { .. } => {
                for (index, text) in responses::reasoning_parts(item).unwrap_or_default() {
                    self.reconcile(index, text);
                }
            }
            SlotBody::ToolCall(call) => call.reconcile(item),
            SlotBody::ToolResult { call_id, output } => {
                let entry = responses::output_entry(item);
                *call_id = entry.call_id;
                *output = entry.text;
            }
            SlotBody::Other(text) => *text = Projection::unknown(item).map(|entry| entry.text),
        }
    }

    /// Reconciles the text and refusal parts of a message snapshot.
    fn reconcile_content(&mut self, item: &Value) {
        match item.get("content") {
            Some(Value::Array(parts)) => {
                for (index, part) in parts.iter().enumerate() {
                    let index = slot_index(index);
                    if let Some(text) = response_part_text(part) {
                        self.reconcile(index, text);
                    } else if part.get("type").and_then(Value::as_str) == Some("refusal")
                        && let Some(refusal) = part.get("refusal").and_then(Value::as_str)
                        && let SlotBody::Message { parts, .. } = &mut self.body
                    {
                        parts.insert(index, Part::Refusal(refusal.to_owned()));
                    }
                }
            }
            Some(Value::String(text)) => self.reconcile(0, text),
            _ => {
                if let Some(text) = item.get("output_text").and_then(Value::as_str) {
                    self.reconcile(0, text);
                }
            }
        }
    }

    /// The item's entries, by the block-to-role table, each carrying the
    /// item's identity.
    fn entries(&self) -> Vec<ConversationEntry> {
        let mut entries = match &self.body {
            SlotBody::Message { parts, calls } => parts
                .values()
                .map(|part| match part {
                    Part::Text(text) => Projection::text(self.role, text),
                    Part::Refusal(text) => Projection::text(EntryRole::Assistant, text),
                })
                .chain(calls.values().map(CallSlot::entry))
                .collect(),
            SlotBody::Reasoning { parts } => vec![Projection::text(
                EntryRole::Reasoning,
                &parts.values().cloned().collect::<Vec<_>>().join("\n"),
            )],
            SlotBody::ToolCall(call) => vec![call.entry()],
            SlotBody::ToolResult { call_id, output } => {
                vec![Projection::tool_result(call_id.clone(), output.clone())]
            }
            SlotBody::Other(text) => text
                .iter()
                .map(|text| Projection::text(EntryRole::Unknown, text))
                .collect(),
        };
        Projection::identify(&mut entries, self.item_id.as_deref());
        entries
    }
}

/// Response-side entries assembled from JSON or streamed documents.
pub struct OpenAiResponse {
    /// Whether no output item, choice, or text was assembled.
    empty: bool,
    /// One entry per output item or content part, in index order.
    entries: Vec<ConversationEntry>,
    /// Decoding state of the response documents.
    completeness: ContentCompleteness,
}

impl OpenAiResponse {
    /// Assembles one response from its decoded documents in arrival order.
    #[must_use]
    pub fn assemble(values: &[Value], incomplete: bool) -> Self {
        let mut slots = BTreeMap::<u64, OutputSlot>::new();
        for value in values {
            if !responses::apply_event(&mut slots, value) {
                Self::apply_document(&mut slots, value);
            }
        }
        Self {
            empty: slots.is_empty(),
            entries: slots.values().flat_map(OutputSlot::entries).collect(),
            completeness: Projection::completeness(!values.is_empty(), incomplete),
        }
    }

    /// Applies a non-streaming Responses object or a Chat Completions document.
    fn apply_document(slots: &mut BTreeMap<u64, OutputSlot>, value: &Value) {
        if let Some(output) = value.get("output").and_then(Value::as_array) {
            responses::apply_output(slots, output);
        } else if let Some(choices) = value.get("choices").and_then(Value::as_array) {
            chat::apply_choices(slots, choices);
        } else if value.get("output_text").is_some() || value.get("content").is_some() {
            Self::reconcile_item(slots, 0, value);
        }
    }

    fn reconcile_item<'slots>(
        slots: &'slots mut BTreeMap<u64, OutputSlot>,
        index: u64,
        item: &Value,
    ) -> &'slots mut OutputSlot {
        let slot = slots
            .entry(index)
            .or_insert_with(|| OutputSlot::new(SlotBody::message()));
        slot.reconcile_item(item);
        slot
    }

    /// Whether no output item, choice, or text was assembled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.empty
    }

    /// Public response conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        Projection::from_entries(self.entries.clone(), self.completeness)
    }
}

/// Returns the text of one response part, excluding refusals and tools.
fn response_part_text(part: &Value) -> Option<&str> {
    match part {
        Value::String(text) => Some(text),
        Value::Object(object) => {
            let text_part = object
                .get("type")
                .and_then(Value::as_str)
                .is_none_or(|kind| {
                    matches!(kind, "output_text" | "text" | "summary_text" | "input_text")
                });
            text_part
                .then(|| object.get("text").and_then(Value::as_str))
                .flatten()
        }
        _ => None,
    }
}

fn slot_index(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn summary(
        conversation: &Conversation,
    ) -> Vec<(EntryRole, &str, Option<&str>, Option<&str>)> {
        conversation
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.role,
                    entry.text.as_str(),
                    entry.call_id.as_deref(),
                    entry.name.as_deref(),
                )
            })
            .collect()
    }

    pub(super) fn item_ids(conversation: &Conversation) -> Vec<Option<&str>> {
        conversation
            .entries
            .iter()
            .map(|entry| entry.item_id.as_deref())
            .collect()
    }
}
