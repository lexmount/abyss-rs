//! Parsed Messages exchange.

use abyss_plugin_protocol::event::Conversation;

use crate::protocol::model::{image::ParsedImageAttachment, usage::TokenUsage};

/// Wire-level values extracted from one Anthropic Messages interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedAnthropicMessagesExchange {
    /// Session/thread id used to group turns.
    pub session_id: String,
    /// Hash of method, host, path, and request body for event correlation.
    pub request_hash: String,
    /// Structured request messages decoded from the request body.
    pub request_conversation: Conversation,
    /// Structured response messages assembled from the response documents.
    pub response_conversation: Conversation,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// The response this request continues after: `previous_message_id` of a
    /// `thread` `continue`.
    pub previous_response_id: Option<String>,
    /// Best token counters found in request or response payloads.
    pub usage: TokenUsage,
    /// Anthropic message id when present.
    pub message_id: Option<String>,
    /// Provider model name.
    pub model: Option<String>,
}
