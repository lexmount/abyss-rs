//! Chat Completions ordered message history projection.

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, MessageRole};
use serde_json::Value;

use crate::protocol::{
    model::conversation::{ConversationProjection, MessageDraft},
    openai::shared::content::OpenAiContent,
    shared::text::{dedupe_texts, non_empty_trimmed},
};

pub struct ChatRequest {
    messages: Vec<MessageDraft>,
    prompt: Option<MessageDraft>,
    completeness: ContentCompleteness,
}

impl ChatRequest {
    pub fn parse(payload: Option<&Value>, truncated: bool) -> Self {
        let messages = payload
            .and_then(|p| p.get("messages"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|m| OpenAiContent::request_item(m, MessageRole::Unknown))
            .collect();
        let prompt = payload
            .and_then(|p| p.get("prompt"))
            .and_then(Value::as_str)
            .and_then(non_empty_trimmed)
            .map(|text| {
                let mut draft = MessageDraft::new(MessageRole::User, None);
                draft.push_part(text);
                draft
            });
        Self {
            messages,
            prompt,
            completeness: ConversationProjection::completeness(payload.is_some(), truncated),
        }
    }
    pub fn texts(&self) -> Vec<String> {
        dedupe_texts(
            self.prompt
                .iter()
                .map(MessageDraft::text)
                .chain(
                    self.messages
                        .iter()
                        .filter(|m| m.role == MessageRole::User)
                        .map(MessageDraft::text),
                )
                .collect(),
        )
    }
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_drafts(
            self.messages.iter().chain(&self.prompt),
            self.completeness,
        )
    }
}
