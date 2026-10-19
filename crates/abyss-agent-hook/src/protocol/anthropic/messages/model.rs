//! Parsed Messages exchange and session identity source.

use std::fmt;

use serde::Serialize;

use crate::protocol::model::{
    image::ParsedImageAttachment, tool::ParsedToolEvent, usage::TokenUsage,
};

/// Source used to derive the protocol session identity.
#[derive(Debug, Clone, Copy, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AnthropicSessionIdSource {
    /// Claude/Anthropic supplied an explicit session or thread id.
    Provider,
    /// No actual session identity was available; events are retained in a host bucket.
    Unattributed,
}

impl fmt::Display for AnthropicSessionIdSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Provider => formatter.write_str("provider"),
            Self::Unattributed => formatter.write_str("unattributed"),
        }
    }
}

/// Wire-level values extracted from one Anthropic Messages interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedAnthropicMessagesExchange {
    /// Normalized request host.
    pub host: String,
    /// Request path used to distinguish Anthropic API families.
    pub path: String,
    /// HTTP method.
    pub method: String,
    /// Transport observed by `abyss-mitm`: `http`, `https`, or `unknown`.
    pub transport: &'static str,
    /// Session/thread id used to group turns.
    pub session_id: String,
    /// Source used to derive `session_id`.
    pub session_id_source: AnthropicSessionIdSource,
    /// Hash of method, host, path, and request body for event correlation.
    pub request_hash: String,
    /// Structured request messages decoded from the request body.
    pub request_conversation: abyss_plugin_protocol::event::Conversation,
    /// Structured response messages assembled from the response documents.
    pub response_conversation: abyss_plugin_protocol::event::Conversation,
    /// User-visible prompt/input fragments derived from the request messages.
    pub request_texts: Vec<String>,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// The response this request continues after: `previous_message_id` of a
    /// `thread` `continue`.
    pub previous_response_id: Option<String>,
    /// Tool results submitted on the request side of this provider call.
    pub request_tool_events: Vec<ParsedToolEvent>,
    /// Tool calls streamed by the response side of this provider call.
    pub response_tool_events: Vec<ParsedToolEvent>,
    /// Model-visible response fragments derived from the response messages.
    pub response_texts: Vec<String>,
    /// Best token counters found in request or response payloads.
    pub usage: TokenUsage,
    /// Anthropic message id when present.
    pub message_id: Option<String>,
    /// Provider model name.
    pub model: Option<String>,
    /// Anthropic API version header when present.
    pub anthropic_version: Option<String>,
    /// Provider event type strings found in response JSON/SSE payloads.
    pub event_types: Vec<String>,
}
