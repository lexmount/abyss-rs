//! What an Agent declares about one request in its own headers and body.
//!
//! Each supported Harness reads its own declarations in its registry entry, so
//! protocol parsers stay limited to provider-level content.

use abyss_plugin_protocol::event::EventPurpose;
use http::HeaderMap;
use serde_json::Value;

/// Request and response material an Agent writes its declarations into.
#[derive(Clone, Copy)]
pub struct DeclarationSource<'a> {
    /// Request headers; `None` where no header describes the request, such as
    /// a WebSocket frame after the upgrade.
    pub headers: Option<&'a HeaderMap>,
    /// Decoded request body, when the protocol sends one per request.
    pub body: Option<&'a Value>,
    /// The OpenAI request `client_metadata` object.
    pub client_metadata: Option<&'a Value>,
    /// Model-visible response text fragments.
    pub response_texts: &'a [String],
}

/// What the Agent declared about a request; empty when it declared nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentDeclaration {
    /// The user turn the request works for.
    pub turn_id: Option<String>,
    /// The thread that sent the request.
    pub stream_id: Option<String>,
    /// Whether the Agent opened the sending thread only to name another session.
    pub naming_thread: bool,
    /// What the Agent made the call for.
    pub purpose: Option<EventPurpose>,
    /// Title the Agent generated for its own session, read from the reply of a
    /// session-title call.
    pub session_title: Option<String>,
}
