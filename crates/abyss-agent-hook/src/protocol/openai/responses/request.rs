//! Responses request instructions, input items and prompt projection.

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, MessageRole};
use serde_json::Value;

use crate::protocol::{
    model::conversation::{ConversationProjection, MessageDraft},
    openai::shared::content::OpenAiContent,
    shared::text::{MAX_PARSE_DEPTH, dedupe_texts, non_empty_trimmed},
};

/// Request-side messages, grouped by the request field that carried them.
pub struct ResponsesRequest {
    /// Responses `instructions`, including an explicitly empty value.
    instructions: Option<MessageDraft>,
    /// Responses `input` items in order.
    input: Vec<MessageDraft>,
    /// Plain string `prompt`.
    prompt: Option<MessageDraft>,
    /// Decoding state of the request body.
    completeness: ContentCompleteness,
}

impl ResponsesRequest {
    /// Projects one request body; `None` means it could not be decoded.
    #[must_use]
    pub fn parse(payload: Option<&Value>, truncated: bool) -> Self {
        let mut request = Self {
            instructions: None,
            input: Vec::new(),
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
        self.instructions.is_none() && self.input.is_empty() && self.prompt.is_none()
    }

    /// Event text: flattened non-tool `input` and the prompt.
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
        dedupe_texts(texts)
    }

    /// Public request conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        let mut conversation = ConversationProjection::from_drafts(
            self.instructions
                .iter()
                .chain(&self.input)
                .chain(&self.prompt),
            self.completeness,
        );
        conversation.instructions_present = self.instructions.is_some();
        conversation
    }
}
