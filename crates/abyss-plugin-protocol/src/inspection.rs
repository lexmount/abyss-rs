//! Request-only Agent inspection values exchanged on a broker plugin session.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::event::{Conversation, EventPurpose, ImageAttachment, LlmProvider};

/// Capabilities selected by a plugin for this connection.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PluginCapability {
    /// Receive the existing observation event stream.
    AgentEvents,
    /// Decide on complete plaintext requests before forwarding.
    AgentRequest,
}

/// Complete decoded bytes, without a lossy UTF-8 conversion.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "encoding", content = "content", rename_all = "snake_case")]
#[non_exhaustive]
pub enum DecodedContent {
    /// UTF-8 text, including JSON and unknown text protocols.
    Utf8(String),
    /// Base64 of a binary payload.
    Base64(String),
}

/// Result of projecting a decoded request onto known Agent protocols.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequestParsingStatus {
    /// Recognized protocol with a decoded JSON request.
    Parsed,
    /// No known protocol matched; complete content remains available.
    UnknownProtocol,
    /// A known protocol did not contain a valid JSON request.
    InvalidPayload,
}

/// Reassembled WebSocket payload type, independent of content encoding.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RequestMessageType {
    Text,
    Binary,
}

/// Source metadata supplied by the ingress; explicit proxy clients have none.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSourceProcess {
    /// OS process identifier.
    pub pid: Option<u32>,
    /// OS process incarnation identifier.
    pub pid_version: Option<u32>,
    /// Process name.
    pub name: Option<String>,
    /// Executable path.
    pub executable_path: Option<String>,
    /// Platform application identity.
    pub application_id: Option<String>,
    /// Runtime entry script path.
    pub entry_point: Option<String>,
    /// Working directory.
    pub working_directory: Option<String>,
}

/// Request-side Harness recognition and declarations, independent of audit policy.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHarness {
    /// Recognized Harness name.
    pub id: String,
    /// Recognized version.
    pub version: Option<String>,
    /// Root user turn declared by the client, including for subagent requests.
    pub turn_id: Option<String>,
    /// Subagent identity explicitly declared by this client.
    pub subagent_id: Option<String>,
    /// Subagent that spawned this one, if declared.
    pub parent_subagent_id: Option<String>,
    /// Declared request purpose.
    pub purpose: Option<EventPurpose>,
}

/// Request-only model projection. Response IDs, output and usage are not invented.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRequestProjection {
    /// Known wire dialect.
    pub protocol: String,
    /// Provider resolved from request routing.
    pub provider: LlmProvider,
    /// Model requested by the caller.
    pub model: Option<String>,
    /// Ordered protocol entries, including instructions, tool calls and results.
    pub conversation: Conversation,
    /// Embedded image content; referenced attachments remain in the original JSON.
    pub attachments: Vec<ImageAttachment>,
    /// Provider tool definitions, retaining provider-specific schemas.
    pub tools: Option<Value>,
    /// Response that this request continues, if declared.
    pub previous_response_id: Option<String>,
}

/// Complete decision context for one HTTP request or client WebSocket data message.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRequestContext {
    /// Stable physical flow identity.
    pub flow_id: String,
    /// Unique request/message correlation identity.
    pub request_id: String,
    /// Transport ingress source label.
    pub ingress: String,
    /// Platform process identity, when available.
    pub source_process: Option<RequestSourceProcess>,
    /// Original destination address.
    pub destination: String,
    /// Destination host recovered by ingress.
    pub destination_host: Option<String>,
    /// TLS SNI, when present.
    pub server_name: Option<String>,
    /// Request authority.
    pub authority: Option<String>,
    /// Credential-free next-hop proxy authority.
    pub proxy_endpoint: Option<String>,
    /// HTTP request or upgrade method.
    pub method: String,
    /// HTTP path and query.
    pub path: String,
    /// Whether content is a complete WebSocket data message.
    pub websocket: bool,
    /// HTTP request number (1) or client data-message number within this flow.
    pub sequence: u64,
    /// Original WebSocket type; null for HTTP, including upgrade requests.
    pub message_type: Option<RequestMessageType>,
    /// Headers as name/value pairs, preserving duplicates. Headers recognized by
    /// the MITM credential-header predicate are omitted.
    pub headers: Vec<(String, String)>,
    /// Complete decoded content.
    pub body: DecodedContent,
    /// Complete parsed JSON when present, including unrecognized fields.
    pub json: Option<Value>,
    /// Projection outcome, also supplied for unknown requests.
    pub parsing_status: RequestParsingStatus,
    /// Available request-side Harness identity and declarations.
    pub harness: Option<RequestHarness>,
    /// Known Agent request projection.
    pub agent: Option<AgentRequestProjection>,
}

/// Plugin reply correlated to one inspection on this connection.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectResponse {
    /// Broker request identifier from the inspection context.
    pub request_id: String,
    /// Whether this plugin permits forwarding.
    pub allow: bool,
    /// Safe client-facing reason. Must not echo sensitive request content.
    pub reason: Option<String>,
}

/// Decision returned by SDK request handlers.
#[derive(Debug)]
#[non_exhaustive]
pub enum RequestDecision {
    /// Permit this request.
    Allow,
    /// Reject this request with a safe explanation.
    Block(String),
}

impl RequestDecision {
    /// Encodes a handler decision for its original request.
    #[must_use]
    pub fn into_response(self, request_id: String) -> InspectResponse {
        let (allow, reason) = match self {
            Self::Allow => (true, None),
            Self::Block(reason) => (false, Some(reason)),
        };
        InspectResponse {
            request_id,
            allow,
            reason,
        }
    }
}
