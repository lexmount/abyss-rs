//! What an Agent declares about one request in its own headers.
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
    /// Headers that describe every request of the connection: a WebSocket
    /// upgrade request's. Agents read only connection-wide declarations, such
    /// as their thread, from them; a request's own headers come first.
    pub connection_headers: Option<&'a HeaderMap>,
    /// The OpenAI request `client_metadata` object.
    pub client_metadata: Option<&'a Value>,
}

/// What the Agent declared about a request; empty when it declared nothing.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AgentDeclaration {
    /// What the Agent made the call for.
    pub purpose: Option<EventPurpose>,
    /// Subagent the request belongs to; absent on the main agent's requests.
    pub subagent_id: Option<String>,
    /// Subagent that spawned this one; absent when the main agent did.
    pub parent_subagent_id: Option<String>,
    /// Root turn the client declares: the user input this request ultimately
    /// works for. A subagent's requests carry the value of the turn that
    /// spawned it; a request the client makes for no turn carries none.
    pub turn_id: Option<String>,
}

impl DeclarationSource<'_> {
    /// The request's own headers, else the connection's.
    #[must_use]
    pub fn request_or_connection_headers(&self) -> Option<&HeaderMap> {
        self.headers.or(self.connection_headers)
    }
}
