//! Projected response content produced by each OpenAI dialect assembler.

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation};

use crate::protocol::{
    model::{
        conversation::{ConversationProjection, MessageDraft},
        tool::ParsedToolEvent,
    },
    shared::text::dedupe_texts,
};

/// Response-side messages assembled from JSON or streamed documents.
pub struct OpenAiResponse {
    /// One message per output item or chat choice, in index order.
    pub messages: Vec<MessageDraft>,
    /// Tool calls ordered by output item, or by Chat choice and tool index.
    pub tool_calls: Vec<ParsedToolEvent>,
    /// Decoding state of the response documents.
    pub completeness: ContentCompleteness,
}

impl OpenAiResponse {
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

    /// Tool calls requested by Responses output items or Chat choices.
    #[must_use]
    pub fn tool_calls(&self) -> Vec<ParsedToolEvent> {
        self.tool_calls.clone()
    }
}
