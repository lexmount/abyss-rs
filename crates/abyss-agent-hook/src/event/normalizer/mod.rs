//! Internal normalized event model for producing public Agent events.

mod anthropic;
mod openai;

use abyss_plugin_protocol::event::{
    AgentContext as PluginAgentContext, AgentEvent, AgentEventSide, ContentCategory, Conversation,
    DeviceContext, EntryRole, EventPurpose, HttpHeader, ImageAttachment, ImageMediaType,
    LlmContext, LlmProvider, TokenUsage as PluginTokenUsage,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::{
    config::{DeviceIdentity, HarnessUsageContentConfig, HarnessUsageHookConfig},
    event::{headers::ExchangeHeaders, identifier::stable_event_id},
    harness::{AgentDeclaration, BuiltInHarness, HarnessDetection},
    protocol::model::digest::sha256_hex,
    protocol::model::image::ParsedImageAttachment,
    protocol::model::usage::{TokenUsage, TokenUsageSource},
};

const UNKNOWN_HOST_NAME: &str = "unknown";

/// Failure while converting one hook-internal event into the plugin contract.
#[derive(Debug, Error)]
pub enum AgentEventConversionError {
    /// The producer timestamp was not valid RFC3339.
    #[error("invalid observed_at timestamp `{value}`: {source}")]
    InvalidTimestamp {
        value: String,
        #[source]
        source: chrono::ParseError,
    },
    /// The normalized event side is not part of protocol version 1.
    #[error("unsupported Agent event side `{value}`")]
    UnsupportedEventSide { value: &'static str },
    /// A token counter was negative before public normalization.
    #[error("{name} must be non-negative, got {value}")]
    NegativeTokenCounter { name: &'static str, value: i64 },
    /// An attachment media type is outside protocol version 1.
    #[error("unsupported image media type `{value}`")]
    UnsupportedImageMediaType { value: &'static str },
    /// An attachment position cannot be represented by the public contract.
    #[error("image attachment position must be non-negative, got {value}")]
    InvalidAttachmentPosition { value: i32 },
}

#[derive(Debug, Clone, Copy)]
enum AgentClientKind {
    Cli,
    Desktop,
}

impl AgentClientKind {
    const fn metadata_value(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Desktop => "desktop",
        }
    }
}

/// One hook-internal normalized usage event.
#[derive(Debug, Serialize)]
pub struct NormalizedUsageEvent {
    /// Stable id assigned by the event producer.
    pub event_id: String,
    /// Capture time in RFC3339 format.
    pub observed_at: String,
    /// Device metadata associated with the local broker.
    pub device: DevicePayload,
    /// Agent metadata inferred from the captured traffic.
    pub agent: AgentPayload,
    /// Provider/session correlation id when available, otherwise a flow-derived id.
    pub session_id: String,
    /// Provider identity of the response this exchange produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    /// The response this exchange's request continues after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Subagent the client declared in its request headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subagent_id: Option<String>,
    /// Spawning subagent the client declared in its request headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_subagent_id: Option<String>,
    /// Root turn the client declared in its request headers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_turn_id: Option<String>,
    /// Purpose the Agent declared for this provider call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<EventPurpose>,
    /// LLM provider and model metadata.
    pub llm: LlmPayload,
    /// Logical event side: currently `request` or `response`.
    pub event_type: &'static str,
    /// Content categories the effective policy omitted from this event.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub omitted: Vec<ContentCategory>,
    /// Role-aware request or response entries after content policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<Conversation>,
    /// Captured headers of this event's side, credential values redacted.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HttpHeader>,
    /// Token counters attributed to this event side.
    pub token_usage: TokenUsage,
    /// Hook-private provider context used while building typed plugin fields.
    pub metadata: Value,
    /// Validated image attachments associated with this event side.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<NormalizedImageAttachment>,
}

impl TryFrom<NormalizedUsageEvent> for AgentEvent {
    type Error = AgentEventConversionError;

    fn try_from(event: NormalizedUsageEvent) -> Result<Self, Self::Error> {
        let NormalizedUsageEvent {
            event_id,
            observed_at,
            device,
            agent,
            session_id,
            response_id,
            previous_response_id,
            subagent_id,
            parent_subagent_id,
            root_turn_id,
            purpose,
            llm,
            event_type,
            omitted,
            conversation,
            headers,
            token_usage,
            metadata: _,
            attachments,
        } = event;
        let occurred_at = DateTime::parse_from_rfc3339(&observed_at)
            .map_err(|source| AgentEventConversionError::InvalidTimestamp {
                value: observed_at,
                source,
            })?
            .with_timezone(&Utc);
        let side = match event_type {
            "request" => AgentEventSide::Request,
            "response" => AgentEventSide::Response,
            value => return Err(AgentEventConversionError::UnsupportedEventSide { value }),
        };

        Ok(Self {
            event_id,
            occurred_at,
            device: DeviceContext {
                host_name: device.host_name,
                platform: device.platform,
                os_version: device.os_version,
            },
            agent: PluginAgentContext {
                name: agent.name,
                version: agent.version,
            },
            session_id,
            response_id,
            previous_response_id,
            subagent_id,
            parent_subagent_id,
            root_turn_id,
            purpose,
            llm: LlmContext {
                provider: LlmProvider::from_wire_name(llm.provider),
                model: llm.model,
            },
            side,
            omitted,
            conversation,
            headers,
            token_usage: token_usage.try_into()?,
            attachments: attachments
                .into_iter()
                .map(ImageAttachment::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<TokenUsage> for PluginTokenUsage {
    type Error = AgentEventConversionError;

    fn try_from(usage: TokenUsage) -> Result<Self, Self::Error> {
        Ok(Self {
            input_tokens: non_negative_counter("input_tokens", usage.input_tokens)?,
            output_tokens: non_negative_counter("output_tokens", usage.output_tokens)?,
            cache_read_tokens: non_negative_counter("cache_read_tokens", usage.cache_read_tokens)?,
            cache_write_tokens: non_negative_counter(
                "cache_write_tokens",
                usage.cache_write_tokens,
            )?,
            reasoning_tokens: non_negative_counter("reasoning_tokens", usage.reasoning_tokens)?,
            total_tokens: non_negative_counter("total_tokens", usage.total_tokens)?,
        })
    }
}

fn non_negative_counter(name: &'static str, value: i64) -> Result<u64, AgentEventConversionError> {
    u64::try_from(value)
        .map_err(|_| AgentEventConversionError::NegativeTokenCounter { name, value })
}

impl TryFrom<NormalizedImageAttachment> for ImageAttachment {
    type Error = AgentEventConversionError;

    fn try_from(attachment: NormalizedImageAttachment) -> Result<Self, Self::Error> {
        let media_type = match attachment.media_type {
            "image/png" => ImageMediaType::Png,
            "image/jpeg" => ImageMediaType::Jpeg,
            "image/webp" => ImageMediaType::Webp,
            "image/gif" => ImageMediaType::Gif,
            value => return Err(AgentEventConversionError::UnsupportedImageMediaType { value }),
        };
        Ok(Self {
            position: u32::try_from(attachment.position).map_err(|_| {
                AgentEventConversionError::InvalidAttachmentPosition {
                    value: attachment.position,
                }
            })?,
            media_type,
            byte_size: attachment.byte_size,
            sha256: attachment.sha256,
            content_base64: attachment.content_base64,
        })
    }
}

/// One validated image attachment carried by a normalized event.
#[derive(Debug, Serialize)]
pub struct NormalizedImageAttachment {
    /// Stable presentation order within the event.
    pub position: i32,
    /// Validated browser-safe image media type.
    pub media_type: &'static str,
    /// Decoded byte count before base64 transport encoding.
    pub byte_size: u64,
    /// SHA-256 digest of the decoded image bytes.
    pub sha256: String,
    /// Image bytes when image collection is enabled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_base64: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DevicePayload {
    /// Human-readable hostname included in the public event context.
    pub host_name: String,
    /// Platform name such as `windows`, `macos`, or `linux`.
    pub platform: String,
    /// Optional OS version if a future platform adapter supplies it.
    pub os_version: Option<String>,
}

impl From<&DeviceIdentity> for DevicePayload {
    fn from(device: &DeviceIdentity) -> Self {
        Self {
            host_name: device
                .hostname
                .clone()
                .unwrap_or_else(|| UNKNOWN_HOST_NAME.to_owned()),
            platform: device
                .platform
                .clone()
                .unwrap_or_else(|| std::env::consts::OS.to_owned()),
            os_version: device.os_version.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct AgentPayload {
    /// Agent product name.
    pub name: String,
    /// Optional agent version inferred from user-agent or provider metadata.
    pub version: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct LlmPayload {
    /// Provider namespace.
    pub provider: String,
    /// Model name or `unknown` when the request/response does not expose it.
    pub model: String,
}

/// Parsed protocol exchange that can be converted by the common event normalizer.
pub trait NormalizableExchange {
    fn session_id(&self) -> &str;

    /// Purpose explicitly declared by the provider protocol, if any.
    fn purpose(&self) -> Option<EventPurpose> {
        None
    }

    /// Provider identities linking the exchange to the responses around it.
    fn continuation(&self) -> Continuation<'_>;

    fn event_parts(
        &self,
        detection: &HarnessDetection,
        provider: &LlmProvider,
    ) -> ParsedEventParts<'_>;
}

/// Normalizes one parsed interaction with independently detected context,
/// what the detected Agent declared about it, and the exchange's captured
/// headers.
pub fn normalize_exchange<E>(
    config: &HarnessUsageHookConfig,
    parsed: &E,
    content: &HarnessUsageContentConfig,
    detection: &HarnessDetection,
    provider: &LlmProvider,
    declaration: &AgentDeclaration,
    headers: &ExchangeHeaders,
) -> Vec<NormalizedUsageEvent>
where
    E: NormalizableExchange,
{
    let parts = parsed.event_parts(detection, provider);
    let continuation = parsed.continuation();
    // Only the traffic names these; without a declaration the events carry none.
    let declared = Declared {
        purpose: parsed.purpose().or(declaration.purpose),
        response_id: continuation.response_id,
        previous_response_id: continuation.previous_response_id,
        subagent_id: declaration.subagent_id.as_deref(),
        parent_subagent_id: declaration.parent_subagent_id.as_deref(),
        root_turn_id: declaration.root_turn_id.as_deref(),
    };
    events_for_parsed_exchange(config, &parts, content, declared, headers)
}

fn harness_client(detection: &HarnessDetection) -> &'static str {
    if detection.harness_id.as_str() == BuiltInHarness::ClaudeDesktop.id() {
        AgentClientKind::Desktop.metadata_value()
    } else {
        AgentClientKind::Cli.metadata_value()
    }
}

pub struct ParsedEventParts<'a> {
    http: HttpMetadata<'a>,
    harness_name: String,
    harness_client: &'static str,
    harness_version: Option<String>,
    llm_provider: String,
    llm_model: Option<String>,
    session_id: String,
    response_identity: String,
    request_conversation: &'a Conversation,
    response_conversation: &'a Conversation,
    request_images: Vec<ParsedImageAttachment>,
    usage: TokenUsage,
    usage_source: TokenUsageSource,
    metadata: Value,
    allow_request_without_response: bool,
}

/// Provider identities linking one exchange to the responses around it.
#[derive(Clone, Copy, Default)]
pub struct Continuation<'a> {
    /// Provider identity of the response.
    pub response_id: Option<&'a str>,
    /// The response the request continues after.
    pub previous_response_id: Option<&'a str>,
}

/// Where one exchange sits, as the Agent and provider declare it in the
/// traffic. Both events of the exchange carry it.
#[derive(Clone, Copy, Default)]
struct Declared<'a> {
    purpose: Option<EventPurpose>,
    response_id: Option<&'a str>,
    previous_response_id: Option<&'a str>,
    subagent_id: Option<&'a str>,
    parent_subagent_id: Option<&'a str>,
    root_turn_id: Option<&'a str>,
}

struct EventSide<'a> {
    event_type: &'static str,
    conversation: &'a Conversation,
    token_usage: TokenUsage,
    metadata: Value,
    attachments: &'a [ParsedImageAttachment],
    headers: &'a [HttpHeader],
    content: &'a HarnessUsageContentConfig,
    declared: Declared<'a>,
}

/// Generates strictly increasing collector timestamps for one normalized
/// provider exchange. Provider request and response events are created only
/// after the terminal response arrives, so wall-clock reads can otherwise
/// collapse to the same timestamp. `PostgreSQL` stores `timestamptz` values at
/// microsecond precision, so the minimum step must survive that boundary.
struct EventTimestampSequence {
    previous: Option<DateTime<Utc>>,
}

impl EventTimestampSequence {
    const fn new() -> Self {
        Self { previous: None }
    }

    fn next(&mut self) -> DateTime<Utc> {
        let now = Utc::now();
        let observed_at = self.previous.map_or(now, |previous| {
            let monotonic = previous
                .checked_add_signed(TimeDelta::microseconds(1))
                .unwrap_or(previous);
            now.max(monotonic)
        });
        self.previous = Some(observed_at);
        observed_at
    }
}

#[derive(Clone)]
struct HttpMetadata<'a> {
    transport: &'static str,
    host: &'a str,
    path: &'a str,
    method: &'a str,
}

fn events_for_parsed_exchange(
    config: &HarnessUsageHookConfig,
    parts: &ParsedEventParts<'_>,
    content: &HarnessUsageContentConfig,
    declared: Declared<'_>,
    headers: &ExchangeHeaders,
) -> Vec<NormalizedUsageEvent> {
    // Most provider hooks wait until a response body or usage appears before
    // emitting events. Claude Desktop private SSE responses do not include
    // authoritative usage, and compressed/streaming response bodies can be
    // unavailable to the first-pass parser. The prompt itself is still a useful
    // desktop audit event when request-only fallback is enabled.
    //
    // A side carries content when its conversation has an entry, before the
    // content policy empties any text.
    let request_has_content =
        !parts.request_conversation.entries.is_empty() || !parts.request_images.is_empty();
    let response_has_content = !parts.response_conversation.entries.is_empty();
    let has_request_only_fallback = parts.allow_request_without_response && request_has_content;
    if !response_has_content && parts.usage.is_empty() && !has_request_only_fallback {
        return Vec::new();
    }

    // Keep provider/raw HTTP context internally while typed fields remain
    // stable for plugin consumers.
    let mut normalized_metadata = json!({
        "capture_mode": "abyss-mitm",
        "agent_product": parts.harness_name,
        "agent_client": parts.harness_client,
        "transport": parts.http.transport,
        "host": parts.http.host,
        "path": parts.http.path,
        "method": parts.http.method,
        "content_policy": content,
    });
    if content.token_usage {
        normalized_metadata["provider_usage"] = json!(parts.usage);
        normalized_metadata["token_usage_source"] = json!(parts.usage_source);
        normalized_metadata["token_usage_estimated"] =
            Value::Bool(parts.usage_source.is_estimated());
    }
    let provider_metadata = projected_provider_metadata(&parts.metadata, content);
    let metadata = merge_metadata(normalized_metadata, &provider_metadata);

    let mut events = Vec::new();
    let mut timestamps = EventTimestampSequence::new();
    let request_usage = parts.usage.request_side();
    if request_has_content || !request_usage.is_empty() {
        events.push(usage_event(
            config,
            parts,
            EventSide {
                event_type: "request",
                conversation: parts.request_conversation,
                token_usage: retained_token_usage(request_usage, content),
                metadata: metadata.clone(),
                attachments: &parts.request_images,
                headers: &headers.request,
                content,
                declared,
            },
            timestamps.next(),
        ));
    }

    let response_usage = parts.usage.response_side();
    if response_has_content || !response_usage.is_empty() {
        events.push(usage_event(
            config,
            parts,
            EventSide {
                event_type: "response",
                conversation: parts.response_conversation,
                token_usage: retained_token_usage(response_usage, content),
                metadata,
                attachments: &[],
                headers: &headers.response,
                content,
                declared,
            },
            timestamps.next(),
        ));
    }

    events
}

fn retained_token_usage(usage: TokenUsage, content: &HarnessUsageContentConfig) -> TokenUsage {
    if content.token_usage {
        usage
    } else {
        TokenUsage::default()
    }
}

/// Applies content policy to one side's conversation.
///
/// Entries keep their role, order, and `item_id`. An omitted category only
/// empties the text: conversation text for non-tool entries, tool content for
/// tool calls and results, which keep their `call_id` and `name`.
fn retained_conversation(
    conversation: &Conversation,
    content: &HarnessUsageContentConfig,
) -> Conversation {
    let mut conversation = conversation.clone();
    for entry in &mut conversation.entries {
        let kept = if matches!(entry.role, EntryRole::ToolCall | EntryRole::ToolResult) {
            content.tool_calls
        } else {
            content.conversation_text
        };
        if !kept {
            entry.text.clear();
        }
    }
    conversation
}

/// Content categories the policy leaves out, in a fixed order.
fn omitted_categories(content: &HarnessUsageContentConfig) -> Vec<ContentCategory> {
    [
        (content.token_usage, ContentCategory::TokenUsage),
        (content.conversation_text, ContentCategory::ConversationText),
        (content.tool_calls, ContentCategory::ToolContent),
        (content.images, ContentCategory::Images),
    ]
    .into_iter()
    .filter_map(|(kept, category)| (!kept).then_some(category))
    .collect()
}

fn projected_provider_metadata(metadata: &Value, content: &HarnessUsageContentConfig) -> Value {
    let mut metadata = metadata.clone();
    let Some(object) = metadata.as_object_mut() else {
        return metadata;
    };

    // Provider event type lists are a raw structural view and can reveal that
    // a disabled tool or image category was present even after the policy
    // empties that content. Keep them only when every normalized event
    // content category is enabled.
    if !content.token_usage || !content.conversation_text || !content.tool_calls || !content.images
    {
        object.remove("provider_event_types");
    }
    if !content.tool_calls {
        object.remove("stop_reason");
    }

    metadata
}

fn usage_event(
    config: &HarnessUsageHookConfig,
    parts: &ParsedEventParts<'_>,
    side: EventSide<'_>,
    observed_at: DateTime<Utc>,
) -> NormalizedUsageEvent {
    let content_hash = event_content_hash(side.conversation, side.attachments);
    // Event ids must remain deterministic across repeated observations.
    let device_event_key = config.device.hostname.as_deref().unwrap_or("");
    let event_id = stable_event_id([
        device_event_key,
        parts.harness_name.as_str(),
        parts.session_id.as_str(),
        side.event_type,
        parts.response_identity.as_str(),
        content_hash.as_str(),
    ]);
    NormalizedUsageEvent {
        event_id,
        observed_at: observed_at.to_rfc3339_opts(SecondsFormat::Micros, true),
        device: DevicePayload::from(&config.device),
        agent: AgentPayload {
            name: parts.harness_name.clone(),
            version: parts.harness_version.clone(),
        },
        session_id: parts.session_id.clone(),
        response_id: side.declared.response_id.map(str::to_owned),
        previous_response_id: side.declared.previous_response_id.map(str::to_owned),
        subagent_id: side.declared.subagent_id.map(str::to_owned),
        parent_subagent_id: side.declared.parent_subagent_id.map(str::to_owned),
        root_turn_id: side.declared.root_turn_id.map(str::to_owned),
        purpose: side.declared.purpose,
        llm: LlmPayload {
            provider: parts.llm_provider.clone(),
            model: parts
                .llm_model
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
        },
        event_type: side.event_type,
        omitted: omitted_categories(side.content),
        conversation: Some(retained_conversation(side.conversation, side.content)),
        headers: side.headers.to_vec(),
        token_usage: side.token_usage,
        metadata: side.metadata,
        attachments: normalized_image_attachments(side.attachments, side.content),
    }
}

/// The content part of an event id: the SHA-256 of the side's conversation
/// entries before content policy, extended by its attachment digests.
///
/// The entries are serialized as a compact JSON array holding one
/// `[role, text, call_id, name, item_id]` array per entry, in order, with
/// absent identities as `null`; completeness is not part of the identity.
fn event_content_hash(
    conversation: &Conversation,
    attachments: &[ParsedImageAttachment],
) -> String {
    let entries = conversation
        .entries
        .iter()
        .map(|entry| {
            json!([
                entry.role,
                entry.text,
                entry.call_id,
                entry.name,
                entry.item_id
            ])
        })
        .collect::<Vec<_>>();
    let entries_hash = sha256_hex(&Value::Array(entries).to_string());
    if attachments.is_empty() {
        return entries_hash;
    }
    let mut identity = entries_hash;
    for attachment in attachments {
        identity.push('\0');
        identity.push_str(&attachment.sha256);
    }
    sha256_hex(&identity)
}

fn normalized_image_attachments(
    images: &[ParsedImageAttachment],
    content: &HarnessUsageContentConfig,
) -> Vec<NormalizedImageAttachment> {
    if !content.images {
        return Vec::new();
    }
    images
        .iter()
        .enumerate()
        .map(|(position, image)| NormalizedImageAttachment {
            position: i32::try_from(position)
                .expect("bounded image attachment position should fit in i32"),
            media_type: image.media_type.as_str(),
            byte_size: u64::try_from(image.byte_size())
                .expect("bounded image attachment size should fit in u64"),
            sha256: image.sha256.clone(),
            content_base64: Some(STANDARD.encode(&image.bytes)),
        })
        .collect()
}

fn merge_metadata(mut base: Value, extra: &Value) -> Value {
    let (Some(base), Some(extra)) = (base.as_object_mut(), extra.as_object()) else {
        return base;
    };
    for (key, value) in extra {
        base.insert(key.clone(), value.clone());
    }
    Value::Object(base.clone())
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::event::{
        AgentEvent, ContentCategory, ContentCompleteness, Conversation, ConversationEntry,
        EntryRole, EventPurpose, LlmProvider,
    };

    use crate::{
        config::{DeviceIdentity, HarnessUsageContentConfig, HarnessUsageHookConfig},
        event::ExchangeHeaders,
        harness::{AgentDeclaration, BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId},
        protocol::{
            anthropic::{
                AnthropicSessionIdSource, ParsedAnthropicMessagesExchange,
                claude_web::{ParsedClaudeWebExchange, conversation::ClaudeWebSessionIdSource},
            },
            model::{
                conversation::ConversationProjection,
                image::ParsedImageAttachment,
                usage::{TokenUsage, TokenUsageSource},
            },
            openai::ParsedOpenAiExchange,
        },
    };

    use super::{normalize_exchange, omitted_categories, retained_conversation};

    #[test]
    fn policy_empties_only_the_omitted_text_and_keeps_identities() {
        let mut source = ConversationProjection::empty();
        source.entries = vec![
            ConversationProjection::text(EntryRole::System, "rules"),
            ConversationProjection::text(EntryRole::User, "visible"),
            ConversationProjection::text(EntryRole::Reasoning, "plan"),
            ConversationProjection::text(EntryRole::Assistant, "answer"),
            ConversationProjection::tool_call(
                Some("call_1".to_owned()),
                Some("Bash".to_owned()),
                "{\"command\":\"ls\"}".to_owned(),
            ),
            ConversationProjection::tool_result(Some("call_1".to_owned()), "out".to_owned()),
        ];
        ConversationProjection::identify(&mut source.entries[2..3], Some("thinking:ab12"));
        ConversationProjection::identify(&mut source.entries[3..4], Some("msg_1"));
        ConversationProjection::identify(&mut source.entries[4..5], Some("fc_1"));
        for conversation_text in [false, true] {
            for tool_calls in [false, true] {
                let content = HarnessUsageContentConfig {
                    token_usage: true,
                    conversation_text,
                    tool_calls,
                    images: true,
                };
                let result = retained_conversation(&source, &content);
                assert_eq!(result.entries.len(), source.entries.len());
                for (kept, original) in result.entries.iter().zip(&source.entries) {
                    assert_eq!(kept.role, original.role);
                    assert_eq!(kept.call_id, original.call_id);
                    assert_eq!(kept.name, original.name);
                    assert_eq!(kept.item_id, original.item_id);
                    let retained =
                        if matches!(original.role, EntryRole::ToolCall | EntryRole::ToolResult) {
                            tool_calls
                        } else {
                            conversation_text
                        };
                    assert_eq!(kept.text.is_empty(), !retained);
                }
            }
        }
        assert_eq!(
            omitted_categories(&HarnessUsageContentConfig {
                token_usage: false,
                conversation_text: true,
                tool_calls: false,
                images: false,
            }),
            [
                ContentCategory::TokenUsage,
                ContentCategory::ToolContent,
                ContentCategory::Images,
            ]
        );
        assert!(omitted_categories(&HarnessUsageContentConfig::default()).is_empty());
    }

    #[test]
    fn openai_normalization_uses_detected_harness_and_provider() {
        let parsed = openai_exchange();
        let detection = detection(BuiltInHarness::Codex, "x-openai-originator");

        let events = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection,
            &LlmProvider::Other("gateway.example".to_owned()),
            &AgentDeclaration::default(),
            &ExchangeHeaders::default(),
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "codex"));
        assert!(
            events
                .iter()
                .all(|event| event.llm.provider == "gateway.example")
        );
        assert!(events.iter().all(|event| event.purpose.is_none()));
        assert_eq!(
            events[0].metadata["source_evidence"][0],
            "header:x-openai-originator"
        );
        assert_eq!(events[0].token_usage.input_tokens, 4);
        assert_eq!(events[1].token_usage.output_tokens, 6);
    }

    #[test]
    fn declared_placement_reaches_both_public_events() {
        let mut parsed = openai_exchange();
        parsed.previous_response_id = Some("response-0".to_owned());
        let declaration = AgentDeclaration {
            purpose: Some(EventPurpose::Compaction),
            ..AgentDeclaration::default()
        };
        let detection = detection(BuiltInHarness::Codex, "x-openai-originator");

        let events = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection,
            &LlmProvider::OpenAi,
            &declaration,
            &ExchangeHeaders::default(),
        );

        assert_eq!(events.len(), 2);
        for event in events {
            let event = AgentEvent::try_from(event).expect("event should convert");
            assert_eq!(event.purpose, Some(EventPurpose::Compaction));
            assert_eq!(event.response_id.as_deref(), Some("response-1"));
            assert_eq!(event.previous_response_id.as_deref(), Some("response-0"));
        }
    }

    #[test]
    fn content_policy_is_applied_after_parsing() {
        let content = HarnessUsageContentConfig {
            token_usage: false,
            conversation_text: false,
            tool_calls: false,
            images: false,
        };

        let events = normalize_exchange(
            &hook_config(),
            &openai_exchange(),
            &content,
            &detection(BuiltInHarness::Codex, "x-openai-originator"),
            &LlmProvider::OpenAi,
            &AgentDeclaration::default(),
            &ExchangeHeaders::default(),
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| {
            event.conversation.as_ref().is_some_and(|conversation| {
                conversation
                    .entries
                    .iter()
                    .all(|entry| entry.text.is_empty())
            })
        }));
        assert!(events.iter().all(|event| event.token_usage.is_empty()));
        assert!(
            events
                .iter()
                .all(|event| event.metadata.get("provider_usage").is_none())
        );
    }

    #[test]
    fn token_only_events_exclude_text_tools_and_images_from_plugin_payload() {
        let mut parsed = openai_exchange();
        parsed.request_images = vec![
            ParsedImageAttachment::from_bytes("image/png", b"\x89PNG\r\n\x1a\nprivate-image")
                .expect("image fixture should be accepted"),
        ];
        parsed
            .request_conversation
            .entries
            .push(ConversationProjection::tool_result(
                Some("call-1".to_owned()),
                "private tool output".to_owned(),
            ));
        parsed
            .response_conversation
            .entries
            .push(ConversationProjection::tool_call(
                Some("call-2".to_owned()),
                Some("shell".to_owned()),
                "private tool input".to_owned(),
            ));

        // Verify the fixture carries every content category before filtering it.
        for retain_content in [true, false] {
            let content = HarnessUsageContentConfig {
                token_usage: true,
                conversation_text: retain_content,
                tool_calls: retain_content,
                images: retain_content,
            };
            let events = normalize_exchange(
                &hook_config(),
                &parsed,
                &content,
                &detection(BuiltInHarness::Codex, "x-openai-originator"),
                &LlmProvider::OpenAi,
                &AgentDeclaration::default(),
                &ExchangeHeaders::default(),
            )
            .into_iter()
            .map(|event| {
                let event = abyss_plugin_protocol::event::AgentEvent::try_from(event)
                    .expect("normalized event should convert");
                serde_json::to_value(event).expect("plugin event should serialize")
            })
            .collect::<Vec<_>>();

            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["token_usage"]["input_tokens"], 4_u64);
            assert_eq!(events[0]["token_usage"]["cache_read_tokens"], 1_u64);
            assert_eq!(events[1]["token_usage"]["output_tokens"], 6_u64);
            assert_eq!(events[1]["token_usage"]["reasoning_tokens"], 2_u64);
            assert_eq!(events[0].get("attachments").is_some(), retain_content);
            for event in &events {
                for entry in event["conversation"]["entries"].as_array().unwrap() {
                    assert_eq!(entry["text"] != "", retain_content, "{entry}");
                }
                assert_eq!(event["session_id"], "session-1");
                for field in ["text", "tool_calls", "tool_results", "metadata"] {
                    assert!(
                        event.get(field).is_none(),
                        "field outside the contract: {field}"
                    );
                }
                if !retain_content {
                    assert!(event.get("attachments").is_none());
                }
            }
        }
    }

    fn anthropic_messages_exchange() -> ParsedAnthropicMessagesExchange {
        ParsedAnthropicMessagesExchange {
            host: "api.anthropic.com".to_owned(),
            path: "/v1/messages".to_owned(),
            method: "POST".to_owned(),
            transport: "https",
            session_id: "session-1".to_owned(),
            session_id_source: AnthropicSessionIdSource::Provider,
            request_hash: "request-hash".to_owned(),
            request_conversation: conversation(EntryRole::User, "hello"),
            response_conversation: conversation(EntryRole::Assistant, "hi"),
            request_images: Vec::new(),
            previous_response_id: None,
            usage: usage(),
            message_id: Some("msg-1".to_owned()),
            model: Some("claude-test".to_owned()),
            anthropic_version: Some("2023-06-01".to_owned()),
            event_types: vec!["message".to_owned()],
        }
    }

    #[test]
    fn anthropic_messages_normalization_does_not_infer_harness_from_protocol() {
        let parsed = anthropic_messages_exchange();
        let detection = HarnessDetection {
            harness_id: harness_id("third-party"),
            evidence: vec![HarnessEvidence::Process("third-party".to_owned())],
            version: Some("1.2.3".to_owned()),
            working_directory: None,
        };

        let events = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection,
            &LlmProvider::Anthropic,
            &AgentDeclaration::default(),
            &ExchangeHeaders::default(),
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "third-party"));
        assert!(
            events
                .iter()
                .all(|event| event.agent.version.as_deref() == Some("1.2.3"))
        );
        assert!(events.iter().all(|event| event.llm.provider == "anthropic"));
    }

    #[test]
    fn claude_web_keeps_request_only_interactions() {
        let parsed = ParsedClaudeWebExchange {
            host: "claude.ai".to_owned(),
            path: "/api/organizations/org/chat_conversations/conversation/completion".to_owned(),
            method: "POST".to_owned(),
            transport: "https",
            session_id: "conversation".to_owned(),
            session_id_source: ClaudeWebSessionIdSource::ConversationPath,
            request_hash: "request-hash".to_owned(),
            request_conversation: conversation(EntryRole::User, "hello"),
            response_conversation: ConversationProjection::empty(),
            request_images: Vec::new(),
            request_file_uuids: Vec::new(),
            usage: TokenUsage::default(),
            usage_source: TokenUsageSource::Absent,
            message_id: None,
            model: None,
            human_message_uuid: Some("human-message".to_owned()),
            assistant_message_uuid: Some("assistant-message".to_owned()),
            stop_reason: None,
            event_types: Vec::new(),
        };

        let events = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection(BuiltInHarness::ClaudeDesktop, "claude-web-path"),
            &LlmProvider::Anthropic,
            &AgentDeclaration::default(),
            &ExchangeHeaders::default(),
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "request");
        assert_eq!(events[0].metadata["agent_client"], "desktop");
        assert_eq!(events[0].metadata["path_kind"], "claude_web_completion");
    }

    #[test]
    fn event_ids_hash_every_entry_field_before_content_policy() {
        let event_id = |parsed: &ParsedOpenAiExchange, content: &HarnessUsageContentConfig| {
            normalize_exchange(
                &hook_config(),
                parsed,
                content,
                &detection(BuiltInHarness::Codex, "x-openai-originator"),
                &LlmProvider::OpenAi,
                &AgentDeclaration::default(),
                &ExchangeHeaders::default(),
            )
            .pop()
            .expect("response event")
            .event_id
        };
        let mut parsed = openai_exchange();
        parsed.response_conversation.entries = vec![ConversationProjection::tool_call(
            Some("call-1".to_owned()),
            Some("shell".to_owned()),
            "{\"command\":\"pwd\"}".to_owned(),
        )];
        let baseline = event_id(&parsed, &HarnessUsageContentConfig::default());
        let redacted = HarnessUsageContentConfig {
            token_usage: false,
            conversation_text: false,
            tool_calls: false,
            images: false,
        };
        assert_eq!(event_id(&parsed, &redacted), baseline);

        let variants: [fn(&mut ConversationEntry); 5] = [
            |entry| entry.role = EntryRole::Unknown,
            |entry| entry.text.push(' '),
            |entry| entry.call_id = None,
            |entry| entry.name = Some("exec".to_owned()),
            |entry| entry.item_id = Some("fc-1".to_owned()),
        ];
        for change in variants {
            let mut changed = parsed.clone();
            change(&mut changed.response_conversation.entries[0]);
            assert_ne!(
                event_id(&changed, &HarnessUsageContentConfig::default()),
                baseline
            );
        }
        let mut partial = parsed;
        partial.response_conversation.completeness = ContentCompleteness::Partial;
        assert_eq!(
            event_id(&partial, &HarnessUsageContentConfig::default()),
            baseline
        );
    }

    #[test]
    fn a_side_without_entries_or_usage_emits_no_event() {
        let mut parsed = openai_exchange();
        parsed.usage = TokenUsage::default();
        parsed.response_conversation = ConversationProjection::empty();

        let events = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection(BuiltInHarness::Codex, "x-openai-originator"),
            &LlmProvider::OpenAi,
            &AgentDeclaration::default(),
            &ExchangeHeaders::default(),
        );
        assert!(events.is_empty());

        // An entry whose text is blank still carries the side.
        parsed.response_conversation = conversation(EntryRole::Reasoning, "");
        let events = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection(BuiltInHarness::Codex, "x-openai-originator"),
            &LlmProvider::OpenAi,
            &AgentDeclaration::default(),
            &ExchangeHeaders::default(),
        );
        assert_eq!(
            events
                .iter()
                .map(|event| event.event_type)
                .collect::<Vec<_>>(),
            ["request", "response"]
        );
    }

    #[test]
    fn both_events_carry_the_declared_ids() {
        let mut response = http::HeaderMap::new();
        response.append("request-id", http::HeaderValue::from_static("req_1"));
        let headers = ExchangeHeaders::new(&http::HeaderMap::new(), &response);
        let parsed = anthropic_messages_exchange();
        let normalize = |declaration: &AgentDeclaration| {
            normalize_exchange(
                &hook_config(),
                &parsed,
                &HarnessUsageContentConfig::default(),
                &detection(BuiltInHarness::ClaudeCode, "x-claude-code-session-id"),
                &LlmProvider::Anthropic,
                declaration,
                &headers,
            )
        };
        let events = normalize(&AgentDeclaration {
            subagent_id: Some("a-2".to_owned()),
            parent_subagent_id: Some("a-1".to_owned()),
            root_turn_id: Some("p-1".to_owned()),
            ..AgentDeclaration::default()
        });
        let undeclared = normalize(&AgentDeclaration::default());

        assert_eq!(events.len(), 2);
        for (event, plain) in events.iter().zip(&undeclared) {
            assert_eq!(event.subagent_id.as_deref(), Some("a-2"));
            assert_eq!(event.parent_subagent_id.as_deref(), Some("a-1"));
            assert_eq!(event.root_turn_id.as_deref(), Some("p-1"));
            // The declared ids never enter the event id.
            assert_eq!(event.event_id, plain.event_id);
            assert_eq!(plain.subagent_id, None);
        }
        let mut events = events.into_iter().map(|event| {
            serde_json::to_value(abyss_plugin_protocol::event::AgentEvent::try_from(event).unwrap())
                .unwrap()
        });
        let (request, reply) = (events.next().unwrap(), events.next().unwrap());
        assert_eq!(request["subagent_id"], "a-2");
        assert_eq!(request["parent_subagent_id"], "a-1");
        assert_eq!(reply["root_turn_id"], "p-1");
        assert_eq!(
            reply["headers"],
            serde_json::json!([{"name": "request-id", "value": "req_1"}])
        );
        let mut undeclared = undeclared.into_iter().map(|event| {
            serde_json::to_value(abyss_plugin_protocol::event::AgentEvent::try_from(event).unwrap())
                .unwrap()
        });
        let plain = undeclared.next().unwrap();
        for field in ["subagent_id", "parent_subagent_id", "root_turn_id"] {
            assert!(
                plain.get(field).is_none(),
                "an undeclared {field} is omitted"
            );
        }
    }

    fn openai_exchange() -> ParsedOpenAiExchange {
        ParsedOpenAiExchange {
            generates_output: None,
            host: "gateway.example".to_owned(),
            path: "/v1/responses".to_owned(),
            method: "POST".to_owned(),
            transport: "https",
            session_id: "session-1".to_owned(),
            request_hash: "request-hash".to_owned(),
            request_conversation: conversation(EntryRole::User, "hello"),
            response_conversation: conversation(EntryRole::Assistant, "hi"),
            request_images: Vec::new(),
            usage: usage(),
            response_id: Some("response-1".to_owned()),
            previous_response_id: None,
            client_metadata: None,
            model: Some("model-test".to_owned()),
            event_types: vec!["response.completed".to_owned()],
        }
    }

    fn conversation(role: EntryRole, text: &str) -> Conversation {
        ConversationProjection::from_entries(
            vec![ConversationProjection::text(role, text)],
            ContentCompleteness::Complete,
        )
    }

    fn usage() -> TokenUsage {
        TokenUsage {
            input_tokens: 4,
            output_tokens: 6,
            cache_read_tokens: 1,
            cache_write_tokens: 0,
            reasoning_tokens: 2,
            total_tokens: 10,
        }
    }

    fn detection(harness: BuiltInHarness, header: &'static str) -> HarnessDetection {
        HarnessDetection {
            harness_id: harness.into(),
            evidence: vec![HarnessEvidence::Header(header)],
            version: None,
            working_directory: Some("/workspace".to_owned()),
        }
    }

    fn harness_id(value: &str) -> HarnessId {
        serde_json::from_value(serde_json::Value::String(value.to_owned())).unwrap()
    }

    fn hook_config() -> HarnessUsageHookConfig {
        HarnessUsageHookConfig::new(DeviceIdentity::new())
    }
}
