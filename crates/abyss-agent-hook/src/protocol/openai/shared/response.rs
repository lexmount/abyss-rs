//! Projected response content produced by each OpenAI dialect assembler.

use abyss_plugin_protocol::event::{ContentCompleteness, Conversation, ConversationEntry};

use crate::protocol::model::conversation::ConversationProjection;

/// Response-side entries assembled from JSON or streamed documents.
pub struct OpenAiResponse {
    /// Whether no output item, choice, or text was assembled.
    pub empty: bool,
    /// One entry per output item or content part, in index order.
    pub entries: Vec<ConversationEntry>,
    /// Decoding state of the response documents.
    pub completeness: ContentCompleteness,
}

impl OpenAiResponse {
    /// Whether no output item, choice, or text was assembled.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.empty
    }

    /// Public response conversation.
    #[must_use]
    pub fn conversation(&self) -> Conversation {
        ConversationProjection::from_entries(self.entries.clone(), self.completeness)
    }
}
