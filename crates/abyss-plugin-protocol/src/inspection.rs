//! Request-only Agent inspection values exchanged on a broker plugin session.

use serde::{Deserialize, Serialize, Serializer, ser::SerializeStruct as _};
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
#[derive(Deserialize, Serialize)]
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
    /// Selected model-service credential, without its authentication scheme prefix.
    pub auth_token: Option<String>,
    /// Whether token actions can be applied at this forwarding boundary.
    pub auth_token_writable: bool,
    /// Whether model actions have a supported protocol write-back location.
    pub model_writable: bool,
    /// Known Agent request projection.
    pub agent: Option<AgentRequestProjection>,
}

impl std::fmt::Debug for AgentRequestContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AgentRequestContext")
            .field("request_id", &self.request_id)
            .field("parsing_status", &self.parsing_status)
            .finish_non_exhaustive()
    }
}

/// Plugin reply correlated to one inspection on this connection.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InspectResponse {
    /// Broker request identifier from the inspection context.
    pub request_id: String,
    /// Explicit forwarding decision and optional semantic actions.
    pub decision: RequestDecision,
}

/// Semantic edits supported by the broker; values are never included in Debug.
#[derive(Serialize, PartialEq, Eq)]
#[serde(
    tag = "op",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum ModifyAction {
    /// Set the credential selected by the target's authentication binding.
    SetAuthToken(String),
    /// Remove the selected credential.
    RemoveAuthToken,
    /// Set the requested model without changing the target or protocol.
    SetModel(String),
    /// Remove the model member, including an explicit null.
    RemoveModel,
}

impl<'de> Deserialize<'de> for ModifyAction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
        #[expect(
            clippy::empty_enum_variants_with_brackets,
            reason = "serde unit variants ignore extra fields; empty struct variants enforce the wire schema"
        )]
        enum WireAction {
            SetAuthToken { value: String },
            RemoveAuthToken {},
            SetModel { value: String },
            RemoveModel {},
        }
        Ok(match WireAction::deserialize(deserializer)? {
            WireAction::SetAuthToken { value } => Self::SetAuthToken(value),
            WireAction::RemoveAuthToken {} => Self::RemoveAuthToken,
            WireAction::SetModel { value } => Self::SetModel(value),
            WireAction::RemoveModel {} => Self::RemoveModel,
        })
    }
}

impl std::fmt::Debug for ModifyAction {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SetAuthToken(_) => "SetAuthToken(<redacted>)",
            Self::RemoveAuthToken => "RemoveAuthToken",
            Self::SetModel(_) => "SetModel(<redacted>)",
            Self::RemoveModel => "RemoveModel",
        })
    }
}

/// Decision returned by SDK request handlers. Context remains read-only.
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestDecision {
    /// Continue without editing the current request.
    Allow,
    /// Reject this request with a safe explanation.
    Block(String),
    /// Apply the ordered actions before invoking the next plugin.
    Modify(Box<[ModifyAction]>),
}

impl RequestDecision {
    /// Encodes a handler decision for its original request.
    #[must_use]
    pub const fn into_response(self, request_id: String) -> InspectResponse {
        InspectResponse {
            request_id,
            decision: self,
        }
    }
}

impl Serialize for RequestDecision {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let fields = if matches!(self, Self::Allow) { 1 } else { 2 };
        let mut object = serializer.serialize_struct("RequestDecision", fields)?;
        match self {
            Self::Allow => object.serialize_field("action", "allow")?,
            Self::Block(reason) => {
                object.serialize_field("action", "block")?;
                object.serialize_field("reason", reason)?;
            }
            Self::Modify(actions) => {
                object.serialize_field("action", "modify")?;
                object.serialize_field("actions", actions)?;
            }
        }
        object.end()
    }
}

impl<'de> Deserialize<'de> for RequestDecision {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
        #[expect(
            clippy::empty_enum_variants_with_brackets,
            reason = "serde unit variants ignore extra fields; empty struct variants enforce the wire schema"
        )]
        enum WireDecision {
            Allow {},
            Block { reason: String },
            Modify { actions: Box<[ModifyAction]> },
        }
        Ok(match WireDecision::deserialize(deserializer)? {
            WireDecision::Allow {} => Self::Allow,
            WireDecision::Block { reason } => Self::Block(reason),
            WireDecision::Modify { actions } => Self::Modify(actions),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decisions_round_trip_explicit_actions_without_context() {
        for value in [
            json!({"action":"allow"}),
            json!({"action":"block","reason":"policy"}),
            json!({"action":"modify","actions":[]}),
            json!({"action":"modify","actions":[{"op":"set_auth_token","value":"private-token"},{"op":"remove_auth_token"},{"op":"set_model","value":"new"},{"op":"remove_model"}]}),
        ] {
            let decision: RequestDecision = serde_json::from_value(value.clone()).unwrap();
            assert!(!format!("{decision:?}").contains("private-token"));
            assert_eq!(serde_json::to_value(decision).unwrap(), value);
        }
        for invalid in [
            json!({"action":"allow","actions":[]}),
            json!({"action":"block"}),
            json!({"action":"modify","actions":[{"op":"set_auth_token"}]}),
            json!({"action":"modify","actions":[{"op":"set_auth_token","value":null}]}),
            json!({"action":"modify","actions":[{"op":"remove_model","value":"bad"}]}),
            json!({"action":"modify","actions":[{"op":"remove_model","value":null}]}),
            json!({"action":"modify","actions":[{"op":"replace_body","value":"bad"}]}),
        ] {
            assert!(
                serde_json::from_value::<RequestDecision>(invalid.clone()).is_err(),
                "unexpectedly accepted {invalid}"
            );
        }
    }
}
