//! OpenAI Responses and Chat Completions conversation projection.
//!
//! Requests map `instructions`, Responses `input` items, Chat `messages`, and a
//! string `prompt` onto ordered messages, together with the continuation id.
//! Responses replay streamed deltas onto
//! per-output slots and reconcile them with provider snapshots, so an answer
//! republished by several terminal events is reported once.

use std::collections::BTreeMap;

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, MessageRole};
use serde_json::Value;

use crate::protocol::model::{
    conversation::{ConversationProjection, MessageDraft},
    text::{MAX_PARSE_DEPTH, dedupe_texts, json_to_text, non_empty_trimmed, visible_text},
    tool::ParsedToolEvent,
};

/// OpenAI-specific text, tool-item, and message-item rules.
pub struct OpenAiContent;

impl OpenAiContent {
    /// Returns the visible text of a content value, skipping tool items.
    #[must_use]
    pub fn text(value: &Value, depth: usize) -> Option<String> {
        visible_text(value, depth, Self::is_tool_item)
    }

    /// Whether an item or part type carries tool calls or tool results.
    #[must_use]
    pub fn is_tool_item(item_type: &str) -> bool {
        matches!(item_type, "tool_call" | "tool_result" | "tool_use")
            || item_type.ends_with("_call")
            || item_type.ends_with("_call_output")
    }

    /// Role of one request or response item.
    fn item_role(item: &Value, default_role: MessageRole) -> MessageRole {
        match item.get("type").and_then(Value::as_str) {
            Some("reasoning") => MessageRole::Reasoning,
            Some(kind) if Self::is_tool_item(kind) => MessageRole::Tool,
            _ => item
                .get("role")
                .and_then(Value::as_str)
                .map_or(default_role, ConversationProjection::role),
        }
    }

    /// Projects one request item; content parts stay separate fragments.
    fn request_item(item: &Value, default_role: MessageRole) -> MessageDraft {
        let role = Self::item_role(item, default_role);
        let mut draft = MessageDraft::new(role, item_id(item));
        let content = if role == MessageRole::Reasoning {
            item.get("summary")
        } else {
            item.get("content")
        };
        match (role, content) {
            (MessageRole::Tool, _) => {}
            (_, Some(Value::Array(parts))) => {
                for part in parts {
                    draft.push_part(
                        &Self::text(part, MAX_PARSE_DEPTH.saturating_sub(1)).unwrap_or_default(),
                    );
                }
            }
            (MessageRole::Reasoning, _) => {}
            _ => draft.push_part(&Self::text(item, MAX_PARSE_DEPTH).unwrap_or_default()),
        }
        draft
    }
}

/// Request-side messages, grouped by the request field that carried them.
pub struct OpenAiRequest {
    /// Responses `instructions`, including an explicitly empty value.
    instructions: Option<MessageDraft>,
    /// Responses `input` items in order.
    input: Vec<MessageDraft>,
    /// Chat Completions `messages` in order.
    messages: Vec<MessageDraft>,
    /// Plain string `prompt`.
    prompt: Option<MessageDraft>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl OpenAiRequest {
    /// Projects one request body; `None` means it could not be decoded.
    #[must_use]
    pub fn parse(payload: Option<&Value>, truncated: bool) -> Self {
        let mut request = Self {
            instructions: None,
            input: Vec::new(),
            messages: Vec::new(),
            prompt: None,
            completeness: ConversationProjection::completeness(payload.is_some(), truncated),
        };
        let Some(payload) = payload else {
            return request;
        };
        request.instructions = payload.get("instructions").map(|instructions| {
            let mut draft = MessageDraft::new(MessageRole::Developer, None);
            draft
                .push_part(&OpenAiContent::text(instructions, MAX_PARSE_DEPTH).unwrap_or_default());
            draft
        });
        request.input = match payload.get("input") {
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    let role = if item.is_string() {
                        MessageRole::User
                    } else {
                        MessageRole::Unknown
                    };
                    OpenAiContent::request_item(item, role)
                })
                .collect(),
            Some(Value::String(text)) => {
                let mut draft = MessageDraft::new(MessageRole::User, None);
                draft.push_part(text);
                vec![draft]
            }
            Some(item @ Value::Object(_)) => {
                vec![OpenAiContent::request_item(item, MessageRole::Unknown)]
            }
            _ => Vec::new(),
        };
        request.messages = payload
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|message| OpenAiContent::request_item(message, MessageRole::Unknown))
            .collect();
        request.prompt = payload
            .get("prompt")
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(|prompt| {
                let mut draft = MessageDraft::new(MessageRole::User, None);
                draft.push_part(prompt);
                draft
            });
        request
    }

    /// Whether the request carried no message-bearing field.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.instructions.is_none()
            && self.input.is_empty()
            && self.messages.is_empty()
            && self.prompt.is_none()
    }

    /// Event text: flattened non-tool `input`, the prompt, and Chat user messages.
    #[must_use]
    pub fn texts(&self) -> Vec<String> {
        let input = self
            .input
            .iter()
            .filter(|draft| !matches!(draft.role, MessageRole::Tool | MessageRole::Reasoning))
            .map(MessageDraft::text)
            .filter(|text| !text.is_empty())
            .collect::<Vec<_>>()
            .join("\n");
        let mut texts = vec![input];
        texts.extend(self.prompt.iter().map(MessageDraft::text));
        texts.extend(
            self.messages
                .iter()
                .filter(|draft| draft.role == MessageRole::User)
                .map(MessageDraft::text),
        );
        dedupe_texts(texts)
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        let mut conversation = ConversationProjection::from_drafts(
            self.instructions
                .iter()
                .chain(&self.input)
                .chain(&self.messages)
                .chain(&self.prompt),
            self.completeness,
        );
        conversation.instructions_present = self.instructions.is_some();
        conversation
    }
}

/// Text slots of one output item or chat choice, keyed by content index.
struct OutputSlot {
    /// Provider item identity.
    id: Option<String>,
    /// Role declared by the item or implied by the delta kind.
    role: MessageRole,
    /// Accumulated or reconciled text per content or summary index.
    parts: BTreeMap<u64, String>,
    /// Tool call the item requests, from its latest snapshot with input.
    tool_call: Option<ParsedToolEvent>,
}

impl OutputSlot {
    const fn new(role: MessageRole) -> Self {
        Self {
            id: None,
            role,
            parts: BTreeMap::new(),
            tool_call: None,
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
        let part = self.parts.entry(index).or_default();
        if let Some(suffix) = authoritative.strip_prefix(part.as_str()) {
            part.push_str(suffix);
        } else {
            authoritative.clone_into(part);
        }
    }

    /// Reconciles identity, role, and every text part of one item snapshot.
    fn reconcile_item(&mut self, item: &Value) {
        if let Some(id) = item_id(item) {
            self.id = Some(id);
        }
        self.role = OpenAiContent::item_role(item, MessageRole::Assistant);
        if let Some(call) = tool_call(item) {
            self.tool_call = Some(call);
        }
        if self.role == MessageRole::Tool {
            return;
        }
        match item.get("content").or_else(|| item.get("summary")) {
            Some(Value::Array(parts)) => {
                for (index, part) in parts.iter().enumerate() {
                    if let Some(text) = response_part_text(part) {
                        self.reconcile(slot_index(index), text);
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

    fn into_draft(self) -> MessageDraft {
        let mut draft = MessageDraft::new(self.role, self.id);
        if self.role != MessageRole::Tool {
            for part in self.parts.values() {
                draft.push_part(part);
            }
        }
        draft
    }
}

/// Response-side messages assembled from JSON or streamed documents.
pub struct OpenAiResponse {
    /// One message per output item or chat choice, in index order.
    messages: Vec<MessageDraft>,
    /// One tool call per tool-call output item, in index order.
    tool_calls: Vec<ParsedToolEvent>,
    /// Decoding state of the response documents.
    completeness: ContentCompleteness,
}

impl OpenAiResponse {
    /// Assembles one response from its decoded documents in arrival order.
    #[must_use]
    pub fn assemble(values: &[Value], incomplete: bool) -> Self {
        let mut slots = BTreeMap::<u64, OutputSlot>::new();
        for value in values {
            Self::apply(&mut slots, value);
        }
        let tool_calls = slots
            .values()
            .filter_map(|slot| slot.tool_call.clone())
            .collect();
        Self {
            messages: slots.into_values().map(OutputSlot::into_draft).collect(),
            tool_calls,
            completeness: ConversationProjection::completeness(!values.is_empty(), incomplete),
        }
    }

    fn apply(slots: &mut BTreeMap<u64, OutputSlot>, value: &Value) {
        let output_index = value["output_index"].as_u64().unwrap_or(0);
        let part_index = value
            .get("content_index")
            .or_else(|| value.get("summary_index"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let reasoning_role = |kind: &str| {
            if kind.starts_with("response.reasoning") {
                MessageRole::Reasoning
            } else {
                MessageRole::Assistant
            }
        };
        match value["type"].as_str().unwrap_or_default() {
            kind @ ("response.output_text.delta" | "response.reasoning_summary_text.delta") => {
                if let Some(delta) = value["delta"].as_str() {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| OutputSlot::new(reasoning_role(kind)))
                        .parts
                        .entry(part_index)
                        .or_default()
                        .push_str(delta);
                }
            }
            kind @ ("response.output_text.done" | "response.reasoning_summary_text.done") => {
                if let Some(text) = value["text"].as_str() {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| OutputSlot::new(reasoning_role(kind)))
                        .reconcile(part_index, text);
                }
            }
            kind @ ("response.content_part.done" | "response.reasoning_summary_part.done") => {
                if let Some(text) = value.get("part").and_then(response_part_text) {
                    slots
                        .entry(output_index)
                        .or_insert_with(|| OutputSlot::new(reasoning_role(kind)))
                        .reconcile(part_index, text);
                }
            }
            "response.output_item.added" | "response.output_item.done" => {
                if let Some(item) = value.get("item") {
                    Self::reconcile_item(slots, output_index, item);
                }
            }
            "response.completed" | "response.done" => {
                if let Some(output) = value.pointer("/response/output").and_then(Value::as_array) {
                    for (index, item) in output.iter().enumerate() {
                        Self::reconcile_item(slots, slot_index(index), item);
                    }
                }
            }
            _ => Self::apply_document(slots, value),
        }
    }

    /// Applies a non-streaming Responses object or a Chat Completions document.
    fn apply_document(slots: &mut BTreeMap<u64, OutputSlot>, value: &Value) {
        if let Some(output) = value.get("output").and_then(Value::as_array) {
            for (index, item) in output.iter().enumerate() {
                Self::reconcile_item(slots, slot_index(index), item);
            }
        } else if let Some(choices) = value.get("choices").and_then(Value::as_array) {
            for choice in choices {
                let index = choice["index"].as_u64().unwrap_or(0);
                if let Some(message) = choice.get("message") {
                    Self::reconcile_item(slots, index, message);
                }
                let fragment = choice
                    .pointer("/delta/content")
                    .or_else(|| choice.get("text"))
                    .and_then(Value::as_str);
                if let Some(fragment) = fragment {
                    slots
                        .entry(index)
                        .or_insert_with(|| OutputSlot::new(MessageRole::Assistant))
                        .parts
                        .entry(0)
                        .or_default()
                        .push_str(fragment);
                }
            }
        } else if value.get("output_text").is_some() || value.get("content").is_some() {
            Self::reconcile_item(slots, 0, value);
        }
    }

    fn reconcile_item(slots: &mut BTreeMap<u64, OutputSlot>, index: u64, item: &Value) {
        slots
            .entry(index)
            .or_insert_with(|| OutputSlot::new(MessageRole::Assistant))
            .reconcile_item(item);
    }

    /// Whether no output item, choice, or text was assembled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    /// Event text: every assembled text part, including reasoning summaries.
    #[must_use]
    pub fn texts(&self) -> Vec<String> {
        dedupe_texts(
            self.messages
                .iter()
                .flat_map(|draft| draft.parts.iter().cloned())
                .collect(),
        )
    }

    /// Public response conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_drafts(&self.messages, self.completeness)
    }

    /// Tool calls the response requests, one per output item.
    #[must_use]
    pub fn tool_calls(&self) -> Vec<ParsedToolEvent> {
        self.tool_calls.clone()
    }
}

/// The tool call a `function_call` or `custom_tool_call` item requests, once
/// its input has arrived; earlier snapshots such as `output_item.added` carry
/// none.
fn tool_call(item: &Value) -> Option<ParsedToolEvent> {
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

fn item_id(item: &Value) -> Option<String> {
    item.get("id").and_then(Value::as_str).map(str::to_owned)
}

fn slot_index(position: usize) -> u64 {
    u64::try_from(position).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn final_items_replace_deltas_without_repeating_messages() {
        let values = vec![
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"hel"}),
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"lo"}),
            json!({"type":"response.output_item.done","output_index":1_i32,"item":{"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]}}),
            json!({"type":"response.completed","response":{"output":[
                {"id":"reason","type":"reasoning","summary":[{"type":"summary_text","text":"thinking"}]},
                {"id":"m1","role":"assistant","content":[{"type":"output_text","text":"hello"}]}
            ]}}),
        ];
        let response = OpenAiResponse::assemble(&values, false);
        let conversation = response.conversation();

        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.messages[0].role, MessageRole::Reasoning);
        assert_eq!(conversation.messages[0].id.as_deref(), Some("reason"));
        assert_eq!(conversation.messages[0].text, "thinking");
        assert_eq!(conversation.messages[1].id.as_deref(), Some("m1"));
        assert_eq!(conversation.messages[1].text, "hello");
        assert_eq!(response.texts(), vec!["thinking", "hello"]);
    }

    #[test]
    fn unfinished_parallel_blocks_keep_order_and_identical_text() {
        let values = vec![
            json!({"type":"response.output_text.delta","output_index":1_i32,"content_index":0_i32,"delta":"same"}),
            json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":1_i32,"delta":"same"}),
            json!({"type":"response.output_text.delta","output_index":0_i32,"content_index":0_i32,"delta":"first"}),
        ];
        let conversation = OpenAiResponse::assemble(&values, true).conversation();

        assert_eq!(conversation.messages.len(), 2);
        assert_eq!(conversation.messages[0].text, "first\nsame");
        assert_eq!(conversation.messages[1].text, "same");
        assert_eq!(conversation.completeness, ContentCompleteness::Partial);
    }

    #[test]
    fn chat_choices_are_independent_and_final_message_is_authoritative() {
        let values = vec![
            json!({"choices":[{"index":0_i32,"delta":{"content":"hel"}},{"index":1_i32,"delta":{"content":"other"}}]}),
            json!({"choices":[{"index":0_i32,"delta":{"content":"lo"}}]}),
            json!({"choices":[{"index":0_i32,"message":{"role":"assistant","content":"corrected"}}]}),
        ];
        let conversation = OpenAiResponse::assemble(&values, false).conversation();

        assert_eq!(conversation.messages[0].text, "corrected");
        assert_eq!(conversation.messages[1].text, "other");
    }

    #[test]
    fn request_preserves_roles_and_repeated_messages() {
        let request = OpenAiRequest::parse(
            Some(&json!({
                "instructions":"", "previous_response_id":"r1",
                "input":[{"role":"developer","content":"rules"},
                    {"role":"user","content":[{"type":"input_text","text":"hello","future":42_i32}]},
                    {"role":"user","content":"hello"},
                    {"type":"function_call_output","call_id":"c1","output":"secret"},
                    {"content":"role unavailable"}]
            })),
            false,
        );
        let conversation = request.conversation();

        assert!(conversation.instructions_present);
        let roles = conversation
            .messages
            .iter()
            .map(|message| message.role)
            .collect::<Vec<_>>();
        assert_eq!(
            roles,
            vec![
                MessageRole::Developer,
                MessageRole::Developer,
                MessageRole::User,
                MessageRole::User,
                MessageRole::Tool,
                MessageRole::Unknown,
            ]
        );
        assert_eq!(conversation.messages[2].text, conversation.messages[3].text);
        assert_eq!(conversation.messages[4].text, "");
        assert_eq!(
            request.texts(),
            vec!["rules\nhello\nhello\nrole unavailable"]
        );
    }

    #[test]
    fn request_text_excludes_tool_results_and_images() {
        let request = OpenAiRequest::parse(
            Some(&json!({"input":[{"role":"user","content":[
                {"type":"input_text","text":"visible"},
                {"type":"tool_result","content":"tool secret"},
                {"type":"input_image","image_url":"image secret"}
            ]}]})),
            false,
        );

        assert_eq!(request.conversation().messages[0].text, "visible");
        assert_eq!(request.texts(), vec!["visible"]);
    }
}
