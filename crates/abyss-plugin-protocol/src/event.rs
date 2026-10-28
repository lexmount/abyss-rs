//! Language-neutral Agent event wire types shared by the broker and Rust SDK.
//!
//! These types are independent of the current backend ingest request. A
//! delivery plugin may translate an event into its destination's API without
//! making that remote API part of the broker contract.
//! Agent event compatibility is part of the broker plugin protocol version, so
//! an individual event does not carry a separate schema version.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
mod conversation;
pub use conversation::{ContentCompleteness, Conversation, ConversationEntry, EntryRole};

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
    /// Provider identity of the response this exchange produced. Both events
    /// of the exchange carry it, and later requests continue after it by this
    /// value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    /// The response this exchange's request continues after; the request then
    /// carries only the messages added since that response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Id of the subagent this exchange belongs to, as the client declared it;
    /// absent for the main agent and for side requests.
    ///
    /// Each declared id is read only from the request headers (for a WebSocket
    /// connection, its upgrade request's), taken verbatim, and absent when no
    /// header declares it; no value is substituted. Both events of an exchange
    /// carry it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<String>,
    /// Id of the subagent that spawned this exchange's subagent, declared like
    /// `subagent_id`; absent when the main agent spawned it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_subagent_id: Option<String>,
    /// Root turn the client declares, like `subagent_id`: the user input this
    /// exchange ultimately works for. A subagent's exchanges carry the value
    /// of the turn that spawned it; an exchange the client makes for no turn
    /// carries none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// What the Agent made this provider call for, when its traffic says so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<EventPurpose>,
    /// Provider and model context.
    pub llm: LlmContext,
    /// Request or response side represented by this event.
    pub side: AgentEventSide,
    /// Content categories the effective content policy omitted from this
    /// event; empty when everything was retained.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<ContentCategory>,
    /// Role-aware request or response entries, one per protocol block or
    /// item; the only carrier of the side's content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation: Option<Conversation>,
    /// The exchange's request target: its path and query as the request named
    /// them (for a WebSocket connection, its upgrade request's), verbatim.
    /// Both events of an exchange carry it.
    pub path: String,
    /// Captured headers of this event's side: request headers on a request
    /// event, response headers on a response event. In capture order,
    /// duplicates kept, verbatim except that credential values are redacted.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HttpHeader>,
    /// Token counters attributed to this event side.
    pub token_usage: TokenUsage,
    /// Policy-retained image attachments.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<ImageAttachment>,
}

/// A category of captured content the content policy can omit.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ContentCategory {
    /// Token counters; when omitted every counter is zero.
    TokenUsage,
    /// Text of non-tool conversation entries; when omitted those entries keep
    /// their role and `item_id` with empty text.
    ConversationText,
    /// Tool arguments and results; when omitted tool entries keep their
    /// `call_id`, `name`, and `item_id` with empty text.
    ToolContent,
    /// Image attachments; when omitted no attachment is carried.
    Images,
}

/// One captured request or response header.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "HttpHeaderWire", into = "HttpHeaderWire")]
pub struct HttpHeader {
    /// Header name as captured.
    pub name: String,
    /// Header value as captured.
    pub value: HttpHeaderValue,
}

/// Captured header value bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpHeaderValue {
    /// The value bytes are valid UTF-8; carried as `value`.
    Text(String),
    /// The value bytes are not valid UTF-8; carried base64-encoded as
    /// `value_base64`.
    Base64(String),
}

/// Wire shape of [`HttpHeader`]: exactly one of `value` and `value_base64`.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct HttpHeaderWire {
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value_base64: Option<String>,
}

impl TryFrom<HttpHeaderWire> for HttpHeader {
    type Error = &'static str;

    fn try_from(wire: HttpHeaderWire) -> Result<Self, Self::Error> {
        let value = match (wire.value, wire.value_base64) {
            (Some(value), None) => HttpHeaderValue::Text(value),
            (None, Some(value)) => HttpHeaderValue::Base64(value),
            _ => return Err("a header carries exactly one of `value` and `value_base64`"),
        };
        Ok(Self {
            name: wire.name,
            value,
        })
    }
}

impl From<HttpHeader> for HttpHeaderWire {
    fn from(header: HttpHeader) -> Self {
        let (value, value_base64) = match header.value {
            HttpHeaderValue::Text(value) => (Some(value), None),
            HttpHeaderValue::Base64(value) => (None, Some(value)),
        };
        Self {
            name: header.name,
            value,
            value_base64,
        }
    }
}

/// Agent-declared reason for a provider call.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventPurpose {
    /// The Agent explicitly disables generation while warming a provider connection.
    /// Its observed usage is retained but is outside completed inference-turn usage.
    Prewarm,
    /// The Agent asks the model to name the session the call belongs to.
    SessionTitle,
    /// The Agent asks the model to summarize the conversation so far, to
    /// continue from the summary instead of the full history.
    Compaction,
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

/// Normalized non-negative token counters.
///
/// Input, cache read, cache write, and output counters are disjoint;
/// `reasoning_tokens` is a breakdown of `output_tokens`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TokenUsage {
    /// Input tokens neither read from nor written into a provider cache.
    pub input_tokens: u64,
    /// Tokens produced by model output, including reasoning.
    pub output_tokens: u64,
    /// Input tokens read from a provider cache.
    pub cache_read_tokens: u64,
    /// Input tokens written into a provider cache.
    pub cache_write_tokens: u64,
    /// Part of `output_tokens` spent in model reasoning traces.
    pub reasoning_tokens: u64,
    /// Sum of input, cache read, cache write, and output counters.
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
    use super::{
        AgentContext, AgentEvent, AgentEventSide, ContentCategory, DeviceContext, HttpHeader,
        HttpHeaderValue, LlmContext, LlmProvider, TokenUsage,
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
        for field in [
            "response_id",
            "previous_response_id",
            "subagent_id",
            "parent_subagent_id",
            "turn_id",
            "purpose",
            "omitted",
            "conversation",
            "headers",
        ] {
            assert!(
                serialized.get(field).is_none(),
                "absent {field} should be omitted"
            );
        }
    }

    #[test]
    fn declared_ids_serialize_verbatim_when_present() {
        let mut event = sample_event(LlmProvider::Anthropic);
        event.subagent_id = Some("agent-2".to_owned());
        event.parent_subagent_id = Some("agent-1".to_owned());
        event.turn_id = Some(" turn {1} ".to_owned());
        let serialized = serde_json::to_value(event).expect("Agent event should serialize");

        assert_eq!(serialized["subagent_id"], "agent-2");
        assert_eq!(serialized["parent_subagent_id"], "agent-1");
        assert_eq!(serialized["turn_id"], " turn {1} ");
        let decoded: AgentEvent =
            serde_json::from_value(serialized).expect("declared ids should round-trip");
        assert_eq!(decoded.turn_id.as_deref(), Some(" turn {1} "));
    }

    #[test]
    fn request_headers_carry_exactly_one_value_form() {
        let mut event = sample_event(LlmProvider::OpenAi);
        event.headers = vec![
            HttpHeader {
                name: "session-id".to_owned(),
                value: HttpHeaderValue::Text("s-1".to_owned()),
            },
            HttpHeader {
                name: "x-binary".to_owned(),
                value: HttpHeaderValue::Base64("//4=".to_owned()),
            },
        ];
        let serialized = serde_json::to_value(event).expect("Agent event should serialize");

        assert_eq!(
            serialized["headers"],
            serde_json::json!([
                {"name": "session-id", "value": "s-1"},
                {"name": "x-binary", "value_base64": "//4="}
            ])
        );
        let decoded: AgentEvent =
            serde_json::from_value(serialized.clone()).expect("headers should round-trip");
        assert_eq!(decoded.headers.len(), 2);
        for invalid in [
            serde_json::json!({"name": "a"}),
            serde_json::json!({"name": "a", "value": "v", "value_base64": "dg=="}),
            serde_json::json!({"name": "a", "value": "v", "raw": true}),
        ] {
            let mut event = serialized.clone();
            event["headers"] = serde_json::json!([invalid]);
            assert!(serde_json::from_value::<AgentEvent>(event).is_err());
        }
    }

    #[test]
    fn omitted_categories_use_snake_case_names() {
        let mut event = sample_event(LlmProvider::OpenAi);
        event.omitted = vec![
            ContentCategory::TokenUsage,
            ContentCategory::ConversationText,
            ContentCategory::ToolContent,
            ContentCategory::Images,
        ];
        let serialized = serde_json::to_value(event).expect("Agent event should serialize");

        assert_eq!(
            serialized["omitted"],
            serde_json::json!(["token_usage", "conversation_text", "tool_content", "images"])
        );
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
    fn retired_content_projections_are_rejected() {
        let serialized = serde_json::to_value(sample_event(LlmProvider::OpenAi))
            .expect("event should serialize");
        for (field, value) in [
            ("text", serde_json::json!("hello")),
            ("tool_calls", serde_json::json!([])),
            ("tool_results", serde_json::json!([])),
        ] {
            let mut event = serialized.clone();
            event[field] = value;
            assert!(
                serde_json::from_value::<AgentEvent>(event).is_err(),
                "{field} is carried only by conversation entries"
            );
        }
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
            response_id: None,
            previous_response_id: None,
            subagent_id: None,
            parent_subagent_id: None,
            turn_id: None,
            purpose: None,
            llm: LlmContext {
                provider,
                model: "gpt-test".to_owned(),
            },
            side: AgentEventSide::Request,
            omitted: Vec::new(),
            conversation: None,
            path: "/v1/responses".to_owned(),
            headers: Vec::new(),
            token_usage: TokenUsage {
                input_tokens: 10,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: 10,
            },
            attachments: Vec::new(),
        }
    }
}
