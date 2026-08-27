//! Language-neutral Agent event wire types shared by the broker and Rust SDK.
//!
//! These types are independent of the current backend ingest request. A
//! delivery plugin may translate an event into its destination's API without
//! making that remote API part of the broker contract.
//! Agent event compatibility is part of the broker plugin protocol version, so
//! an individual event does not carry a separate schema version.

use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
/// One event decoded with the contract defined by the active plugin protocol.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentEvent {
    /// Stable event identifier assigned by the event producer.
    pub event_id: String,
    /// Time at which the broker observed the logical event.
    pub occurred_at: DateTime<Utc>,
    /// Device context observed by the broker.
    pub device: DeviceContext,
    /// Agent product context inferred from traffic.
    pub agent: AgentContext,
    /// Provider or collector session identifier.
    pub session_id: String,
    /// One-based collector turn index within the session.
    pub turn_index: NonZeroU32,
    /// Provider and model context.
    pub llm: LlmContext,
    /// Request or response side represented by this event.
    pub side: AgentEventSide,
    /// Policy-retained request or response text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Token counters attributed to this event side.
    pub token_usage: TokenUsage,
    /// Normalized tool calls associated with this event side.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
    /// Normalized tool results associated with this event side.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_results: Vec<ToolResult>,
    /// Policy-retained image attachments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<ImageAttachment>,
}

/// Device context attached to one Agent event.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceContext {
    /// Human-readable host name.
    pub host_name: String,
    /// Platform namespace such as `linux`, `macos`, or `windows`.
    pub platform: String,
    /// Operating-system version when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
}

/// Agent product context attached to one Agent event.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentContext {
    /// Product name such as `codex` or `claude-code`.
    pub name: String,
    /// Agent version when it can be inferred from traffic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// LLM provider and model context attached to one Agent event.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LlmContext {
    /// Provider namespace with typed variants for built-in providers.
    pub provider: LlmProvider,
    /// Provider model name.
    pub model: String,
}

/// Known and extension LLM provider namespaces.
#[derive(Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LlmProvider {
    /// OpenAI-compatible first-party API traffic.
    OpenAi,
    /// Anthropic first-party API traffic.
    Anthropic,
    /// Provider namespace not yet represented by a built-in variant.
    Other(String),
}

impl LlmProvider {
    /// Creates a provider from its wire namespace.
    #[must_use]
    pub fn from_wire_name(provider: String) -> Self {
        match provider.as_str() {
            "openai" => Self::OpenAi,
            "anthropic" => Self::Anthropic,
            _ => Self::Other(provider),
        }
    }

    /// Returns the provider namespace carried on the wire.
    #[must_use]
    pub fn wire_name(&self) -> &str {
        match self {
            Self::OpenAi => "openai",
            Self::Anthropic => "anthropic",
            Self::Other(provider) => provider,
        }
    }
}

impl Serialize for LlmProvider {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.wire_name())
    }
}

impl<'de> Deserialize<'de> for LlmProvider {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Self::from_wire_name)
    }
}

/// Request or response side represented by one usage event.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AgentEventSide {
    /// Agent request content and input-side token usage.
    Request,
    /// Provider response content and output-side token usage.
    Response,
}

impl AgentEventSide {
    /// Returns the request/response name carried by backend translations.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// One normalized model-requested tool invocation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    /// Broker-normalized identifier shared with the corresponding tool result.
    pub call_id: String,
    /// Broker-normalized tool name, such as `Bash`, `Read`, or `exec`.
    pub name: String,
    /// Complete provider-visible tool input normalized as text by the broker.
    pub input: String,
    /// Lowercase SHA-256 digest of `input`.
    pub input_sha256: String,
}

/// One normalized result submitted back to the model after a tool call.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResult {
    /// Broker-normalized identifier shared with the originating tool call.
    pub call_id: String,
    /// Provider-visible result normalized as text by the broker.
    pub output: String,
    /// Lowercase SHA-256 digest of `output`.
    pub output_sha256: String,
}

/// Normalized non-negative token counters.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenUsage {
    /// Tokens consumed by prompt or input content.
    pub input_tokens: u64,
    /// Tokens produced by model output.
    pub output_tokens: u64,
    /// Input tokens read from a provider cache.
    pub cache_read_tokens: u64,
    /// Input tokens written into a provider cache.
    pub cache_write_tokens: u64,
    /// Tokens spent in model reasoning traces.
    pub reasoning_tokens: u64,
    /// Provider total or a total derived by the producer.
    pub total_tokens: u64,
}

/// One policy-retained image attachment.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImageAttachment {
    /// Stable zero-based presentation position within the event.
    pub position: u32,
    /// Validated image media type.
    pub media_type: ImageMediaType,
    /// Decoded byte count before base64 transport encoding.
    pub byte_size: u64,
    /// Lowercase SHA-256 digest of the decoded image bytes.
    pub sha256: String,
    /// Image content when policy permits full image retention.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
}

/// Image media types supported by broker plugin protocol version 1.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ImageMediaType {
    /// Portable Network Graphics.
    #[serde(rename = "image/png")]
    Png,
    /// Joint Photographic Experts Group image.
    #[serde(rename = "image/jpeg")]
    Jpeg,
    /// WebP image.
    #[serde(rename = "image/webp")]
    Webp,
    /// Graphics Interchange Format image.
    #[serde(rename = "image/gif")]
    Gif,
}

impl ImageMediaType {
    /// Returns the MIME type carried on the wire.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
            Self::Gif => "image/gif",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use super::{
        AgentContext, AgentEvent, AgentEventSide, DeviceContext, LlmContext, LlmProvider,
        TokenUsage, ToolCall, ToolResult,
    };
    use chrono::{TimeZone as _, Utc};

    #[test]
    fn agent_event_serializes_as_one_flat_typed_payload() {
        let event = sample_event(LlmProvider::OpenAi);
        let serialized = serde_json::to_value(event).expect("Agent event should serialize");

        assert!(
            serialized.get("schema_version").is_none(),
            "Agent events should be versioned by the plugin protocol"
        );
        assert_eq!(
            serialized["side"], "request",
            "the event side should be a direct typed field"
        );
        assert!(
            serialized.get("event_type").is_none() && serialized.get("payload").is_none(),
            "a single event kind should not add a speculative discriminator or payload wrapper"
        );
        assert!(
            serialized.get("metadata").is_none(),
            "the public event must not expose an unstructured metadata object"
        );
        assert!(
            serialized.get("text").is_none(),
            "absent optional content should be omitted"
        );
    }

    #[test]
    fn tool_activity_serializes_as_named_structures() {
        let mut event = sample_event(LlmProvider::OpenAi);
        event.tool_calls.push(ToolCall {
            call_id: "call-1".to_owned(),
            name: "exec".to_owned(),
            input: "pwd".to_owned(),
            input_sha256: "call-hash".to_owned(),
        });
        event.tool_results.push(ToolResult {
            call_id: "call-1".to_owned(),
            output: "/workspace".to_owned(),
            output_sha256: "result-hash".to_owned(),
        });

        let serialized = serde_json::to_value(event).expect("Agent event should serialize");

        assert_eq!(serialized["tool_calls"][0]["name"], "exec");
        assert_eq!(serialized["tool_calls"][0]["input"], "pwd");
        assert_eq!(serialized["tool_results"][0]["call_id"], "call-1");
        assert_eq!(serialized["tool_results"][0]["output"], "/workspace");
    }

    #[test]
    fn agent_event_rejects_an_unstructured_metadata_object() {
        let mut serialized = serde_json::to_value(sample_event(LlmProvider::OpenAi))
            .expect("event should serialize");
        serialized["metadata"] = serde_json::json!({"provider_private_field": true});

        let error = serde_json::from_value::<AgentEvent>(serialized)
            .expect_err("undeclared metadata should be rejected");

        assert!(
            error.to_string().contains("unknown field `metadata`"),
            "error should identify metadata as outside the public contract"
        );
    }

    #[test]
    fn extension_provider_namespace_round_trips() {
        let serialized = serde_json::to_value(sample_event(LlmProvider::Other(
            "customer-private-llm".to_owned(),
        )))
        .expect("Agent event should serialize");
        let decoded: AgentEvent =
            serde_json::from_value(serialized).expect("Agent event should deserialize");

        assert_eq!(
            decoded.llm.provider,
            LlmProvider::Other("customer-private-llm".to_owned()),
            "unknown provider namespaces should be preserved"
        );
    }

    fn sample_event(provider: LlmProvider) -> AgentEvent {
        AgentEvent {
            event_id: "evt-test".to_owned(),
            occurred_at: Utc
                .with_ymd_and_hms(2026, 8, 19, 10, 0, 0)
                .single()
                .expect("sample timestamp should be valid"),
            device: DeviceContext {
                host_name: "test-host".to_owned(),
                platform: "macos".to_owned(),
                os_version: None,
            },
            agent: AgentContext {
                name: "codex".to_owned(),
                version: None,
            },
            session_id: "session-1".to_owned(),
            turn_index: NonZeroU32::new(1).expect("one should be non-zero"),
            llm: LlmContext {
                provider,
                model: "gpt-test".to_owned(),
            },
            side: AgentEventSide::Request,
            text: None,
            token_usage: TokenUsage {
                input_tokens: 10,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: 10,
            },
            tool_calls: Vec::new(),
            tool_results: Vec::new(),
            attachments: Vec::new(),
        }
    }
}
