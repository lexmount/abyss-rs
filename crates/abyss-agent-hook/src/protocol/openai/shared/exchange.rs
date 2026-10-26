//! Parsed OpenAI-family exchange values consumed by event normalization.

use serde_json::Value;

use crate::protocol::model::{image::ParsedImageAttachment, usage::TokenUsage};

/// Wire-level values extracted from one OpenAI-compatible interaction.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedOpenAiExchange {
    /// WebSocket client generation mode. Only `response.create` with the boolean
    /// `generate: false` disables it; server frames and HTTP exchanges carry none.
    pub generates_output: Option<bool>,
    /// Normalized request host.
    pub host: String,
    /// Request path used to distinguish OpenAI/Codex API families.
    pub path: String,
    /// HTTP method.
    pub method: String,
    /// Transport observed by `abyss-mitm`: `http`, `https`, or `unknown`.
    pub transport: &'static str,
    /// Session/thread id used to group turns. A request-derived fallback is used
    /// for HTTP when client headers do not expose one.
    pub session_id: String,
    /// Hash of method, host, path, and request body for fallback correlation.
    pub request_hash: String,
    /// Structured request messages decoded from the request body.
    pub request_conversation: abyss_plugin_protocol::event::Conversation,
    /// Structured response messages assembled from the response documents.
    pub response_conversation: abyss_plugin_protocol::event::Conversation,
    /// Validated image attachments embedded in user request content.
    pub request_images: Vec<ParsedImageAttachment>,
    /// Best token counters found in request or response payloads.
    pub usage: TokenUsage,
    /// Provider response id when present.
    pub response_id: Option<String>,
    /// The response this request continues after: the request body
    /// `previous_response_id`.
    pub previous_response_id: Option<String>,
    /// The request `client_metadata` object, where a client may declare its
    /// own context; read by the Harness registry.
    pub client_metadata: Option<Value>,
    /// Provider model name.
    pub model: Option<String>,
    /// Provider event type strings found in response JSON/SSE payloads.
    pub event_types: Vec<String>,
}
