//! Protocol-neutral conversation assembly.
//!
//! Provider modules own wire shapes and turn them into [`MessageDraft`]s. A
//! draft keeps the text fragments of one message apart, so the public
//! conversation and the event `text` projection are both derived from a single
//! extraction pass over the decoded documents.

use abyss_plugin_protocol::event::{
    ContentCompleteness, Conversation, ConversationMessage, MessageRole,
};

use crate::protocol::shared::text::non_empty_trimmed;

/// Constructors for public conversation values.
pub struct ConversationProjection;

impl ConversationProjection {
    /// Returns a completely decoded conversation without messages.
    #[must_use]
    pub const fn empty() -> Conversation {
        Conversation {
            messages: Vec::new(),
            instructions_present: false,
            completeness: ContentCompleteness::Complete,
            policy_omitted: false,
        }
    }

    /// Returns the decoding state of one side; truncation outranks decoding.
    #[must_use]
    pub const fn completeness(decoded: bool, truncated: bool) -> ContentCompleteness {
        if truncated {
            ContentCompleteness::Partial
        } else if decoded {
            ContentCompleteness::Complete
        } else {
            ContentCompleteness::Unsupported
        }
    }

    /// Downgrades a completely decoded conversation after a decoding failure.
    pub fn mark_partial(conversation: &mut Conversation) {
        if conversation.completeness == ContentCompleteness::Complete {
            conversation.completeness = ContentCompleteness::Partial;
        }
    }

    /// Builds a conversation from ordered drafts without request metadata.
    #[must_use]
    pub fn from_drafts<'a, I>(drafts: I, completeness: ContentCompleteness) -> Conversation
    where
        I: IntoIterator<Item = &'a MessageDraft>,
    {
        let mut conversation = Self::empty();
        conversation.messages = drafts.into_iter().map(MessageDraft::message).collect();
        conversation.completeness = completeness;
        conversation
    }

    /// Maps a provider-declared role onto the public role set.
    #[must_use]
    pub fn role(value: &str) -> MessageRole {
        match value.trim().to_ascii_lowercase().as_str() {
            "system" => MessageRole::System,
            "developer" => MessageRole::Developer,
            "user" | "human" => MessageRole::User,
            "assistant" => MessageRole::Assistant,
            "tool" | "function" => MessageRole::Tool,
            _ => MessageRole::Unknown,
        }
    }
}

/// One conversation message under assembly.
///
/// `parts` are trimmed, non-empty text fragments in provider order, such as
/// request content blocks or streamed response slots. The public message joins
/// them with a newline; the event `text` projection may keep them apart.
pub struct MessageDraft {
    /// Provider item or message identity, when supplied.
    pub id: Option<String>,
    /// Public role of this message.
    pub role: MessageRole,
    /// Visible text fragments, excluding tool arguments and results.
    pub parts: Vec<String>,
}

impl MessageDraft {
    /// Starts an empty message.
    #[must_use]
    pub const fn new(role: MessageRole, id: Option<String>) -> Self {
        Self {
            id,
            role,
            parts: Vec::new(),
        }
    }

    /// Appends one fragment when it carries visible text.
    pub fn push_part(&mut self, text: &str) {
        if let Some(text) = non_empty_trimmed(text) {
            self.parts.push(text.to_owned());
        }
    }

    /// Returns the public message text.
    #[must_use]
    pub fn text(&self) -> String {
        self.parts.join("\n")
    }

    fn message(&self) -> ConversationMessage {
        ConversationMessage {
            id: self.id.clone(),
            role: self.role,
            text: self.text(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conversation() -> Conversation {
        let mut draft = MessageDraft::new(MessageRole::User, Some("m1".to_owned()));
        draft.push_part("  visible ");
        draft.push_part(" ");
        draft.push_part("second");
        ConversationProjection::from_drafts([&draft], ContentCompleteness::Complete)
    }

    #[test]
    fn drafts_join_trimmed_parts_and_keep_identity() {
        let conversation = conversation();
        assert_eq!(conversation.messages.len(), 1);
        assert_eq!(conversation.messages[0].text, "visible\nsecond");
        assert_eq!(conversation.messages[0].id.as_deref(), Some("m1"));
        assert_eq!(conversation.messages[0].role, MessageRole::User);
    }

    #[test]
    fn roles_map_to_the_public_role_set() {
        assert_eq!(ConversationProjection::role("Human"), MessageRole::User);
        assert_eq!(
            ConversationProjection::role("developer"),
            MessageRole::Developer
        );
        assert_eq!(ConversationProjection::role("other"), MessageRole::Unknown);
    }
}
