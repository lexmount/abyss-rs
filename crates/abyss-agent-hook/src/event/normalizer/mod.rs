//! Internal normalized event model for producing public Agent events.

mod anthropic;
mod openai;

use abyss_plugin_protocol::event::{
    AgentContext as PluginAgentContext, AgentEvent, AgentEventSide, Conversation, DeviceContext,
    EventPurpose, ImageAttachment, ImageMediaType, LlmContext, LlmProvider,
    TokenUsage as PluginTokenUsage, ToolCall, ToolResult,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, TimeDelta, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::{
    config::{DeviceIdentity, HarnessUsageContentConfig, HarnessUsageHookConfig},
    event::identifier::stable_event_id,
    harness::{AgentDeclaration, BuiltInHarness, HarnessDetection},
    protocol::model::image::ParsedImageAttachment,
    protocol::model::tool::ParsedToolEvent,
    protocol::model::usage::{TokenUsage, TokenUsageSource},
    protocol::shared::digest::sha256_hex,
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
    /// A known structured tool segment omitted a required string field.
    #[error("structured content segment is missing string field `{field}`")]
    MissingToolField { field: &'static str },
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
    /// The user turn this request works for, as the Agent declares it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// Whether the Agent opened the sending thread only to name another session.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub naming_thread: bool,
    /// The thread that sent this exchange's request, as the Agent declares it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    /// Provider identity of the response this exchange produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    /// The response this exchange's request continues after.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    /// Purpose the Agent declared for this provider call.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub purpose: Option<EventPurpose>,
    /// Title the Agent generated for this event's session.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_title: Option<String>,
    /// LLM provider and model metadata.
    pub llm: LlmPayload,
    /// Logical event side: currently `request` or `response`.
    pub event_type: &'static str,
    /// Plaintext request or response content extracted by the hook.
    pub text: Option<String>,
    /// Structured provider content retained independently of the text projection.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conversation: Option<Conversation>,
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
            turn_id,
            naming_thread,
            stream_id,
            response_id,
            previous_response_id,
            purpose,
            session_title,
            llm,
            event_type,
            text,
            conversation,
            token_usage,
            metadata,
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
        let (tool_calls, tool_results) = plugin_tool_activity(metadata)?;

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
            turn_id,
            naming_thread,
            stream_id,
            response_id,
            previous_response_id,
            purpose,
            session_title,
            llm: LlmContext {
                provider: LlmProvider::from_wire_name(llm.provider),
                model: llm.model,
            },
            side,
            text,
            conversation,
            token_usage: token_usage.try_into()?,
            tool_calls,
            tool_results,
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

fn plugin_tool_activity(
    mut metadata: Value,
) -> Result<(Vec<ToolCall>, Vec<ToolResult>), AgentEventConversionError> {
    let segments = metadata
        .as_object_mut()
        .and_then(|metadata| metadata.remove("content_segments"))
        .and_then(|segments| match segments {
            Value::Array(segments) => Some(segments),
            _ => None,
        })
        .unwrap_or_default();

    segments.into_iter().try_fold(
        (Vec::new(), Vec::new()),
        |(mut tool_calls, mut tool_results), segment| {
            let Value::Object(mut segment) = segment else {
                return Ok((tool_calls, tool_results));
            };
            match take_segment_string(&mut segment, "type").as_deref() {
                Ok("tool_call") => tool_calls.push(ToolCall {
                    call_id: take_segment_string(&mut segment, "call_id")?,
                    name: take_segment_string(&mut segment, "name")?,
                    input: take_segment_string(&mut segment, "input")?,
                    input_sha256: take_segment_string(&mut segment, "input_sha256")?,
                }),
                Ok("tool_result") => tool_results.push(ToolResult {
                    call_id: take_segment_string(&mut segment, "call_id")?,
                    output: take_segment_string(&mut segment, "output")?,
                    output_sha256: take_segment_string(&mut segment, "output_sha256")?,
                }),
                Ok(_) | Err(_) => {}
            }
            Ok((tool_calls, tool_results))
        },
    )
}

fn take_segment_string(
    segment: &mut Map<String, Value>,
    field: &'static str,
) -> Result<String, AgentEventConversionError> {
    segment
        .remove(field)
        .and_then(|value| match value {
            Value::String(value) => Some(value),
            _ => None,
        })
        .ok_or(AgentEventConversionError::MissingToolField { field })
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
        content: &HarnessUsageContentConfig,
        detection: &HarnessDetection,
        provider: &LlmProvider,
    ) -> ParsedEventParts<'_>;
}

/// Normalizes one parsed interaction with independently detected context and
/// what the detected Agent declared about it.
pub fn normalize_exchange<E>(
    config: &HarnessUsageHookConfig,
    parsed: &E,
    content: &HarnessUsageContentConfig,
    detection: &HarnessDetection,
    provider: &LlmProvider,
    declaration: &AgentDeclaration,
) -> Vec<NormalizedUsageEvent>
where
    E: NormalizableExchange,
{
    let mut parts = parsed.event_parts(content, detection, provider);
    if let Some(session_id) = &declaration.session_id {
        parts.session_id.clone_from(session_id);
    }
    let continuation = parsed.continuation();
    // Only the traffic names these; without a declaration the events carry none.
    let declared = Declared {
        turn_id: declaration.turn_id.as_deref(),
        naming_thread: declaration.naming_thread,
        stream_id: declaration.stream_id.as_deref(),
        purpose: parsed.purpose().or(declaration.purpose),
        session_title: declaration.session_title.as_deref(),
        response_id: continuation.response_id,
        previous_response_id: continuation.previous_response_id,
    };
    events_for_parsed_exchange(config, &parts, content, declared)
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
    request_text: String,
    request_images: Vec<ParsedImageAttachment>,
    response_text: String,
    usage: TokenUsage,
    usage_source: TokenUsageSource,
    metadata: Value,
    request_metadata: Value,
    response_metadata: Value,
    request_has_structured_content: bool,
    response_has_structured_content: bool,
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
    turn_id: Option<&'a str>,
    naming_thread: bool,
    stream_id: Option<&'a str>,
    purpose: Option<EventPurpose>,
    /// Title the Agent generated for its session; only the response carries it.
    session_title: Option<&'a str>,
    response_id: Option<&'a str>,
    previous_response_id: Option<&'a str>,
}

struct EventSide<'a> {
    event_type: &'static str,
    conversation: &'a Conversation,
    text: &'a str,
    token_usage: TokenUsage,
    metadata: Value,
    attachments: &'a [ParsedImageAttachment],
    content: &'a HarnessUsageContentConfig,
    declared: Declared<'a>,
    session_title: Option<&'a str>,
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
) -> Vec<NormalizedUsageEvent> {
    // Most provider hooks wait until a response body or usage appears before
    // emitting events. Claude Desktop private SSE responses do not include
    // authoritative usage, and compressed/streaming response bodies can be
    // unavailable to the first-pass parser. The prompt itself is still a useful
    // desktop audit event when request-only fallback is enabled.
    let has_request_only_fallback = parts.allow_request_without_response
        && (!parts.request_text.is_empty()
            || !parts.request_images.is_empty()
            || parts.request_has_structured_content);
    if parts.response_text.is_empty()
        && parts.usage.is_empty()
        && !parts.response_has_structured_content
        && !has_request_only_fallback
    {
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
    if !parts.request_text.is_empty()
        || !parts.request_images.is_empty()
        || !request_usage.is_empty()
        || parts.request_has_structured_content
    {
        let request_metadata = merge_metadata(metadata.clone(), &parts.request_metadata);
        events.push(usage_event(
            config,
            parts,
            EventSide {
                event_type: "request",
                conversation: parts.request_conversation,
                text: &parts.request_text,
                token_usage: retained_token_usage(request_usage, content),
                metadata: request_metadata,
                attachments: &parts.request_images,
                content,
                declared,
                session_title: None,
            },
            timestamps.next(),
        ));
    }

    let response_usage = parts.usage.response_side();
    if !parts.response_text.is_empty()
        || !response_usage.is_empty()
        || parts.response_has_structured_content
    {
        let response_metadata = merge_metadata(metadata, &parts.response_metadata);
        events.push(usage_event(
            config,
            parts,
            EventSide {
                event_type: "response",
                conversation: parts.response_conversation,
                text: &parts.response_text,
                token_usage: retained_token_usage(response_usage, content),
                metadata: response_metadata,
                attachments: &[],
                content,
                declared,
                session_title: declared.session_title,
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
/// Message text never contains tool arguments, tool results, or image bytes,
/// so only the conversation-text category gates it.
fn retained_conversation(
    conversation: &Conversation,
    content: &HarnessUsageContentConfig,
) -> Conversation {
    let mut conversation = conversation.clone();
    if !content.conversation_text {
        conversation.messages.clear();
        conversation.policy_omitted = true;
    }
    conversation
}

fn content_segments_metadata(
    tool_events: &[ParsedToolEvent],
    images: &[ParsedImageAttachment],
    content: &HarnessUsageContentConfig,
) -> Value {
    if (!content.tool_calls || tool_events.is_empty()) && (!content.images || images.is_empty()) {
        return json!({});
    }

    let mut content_segments = Vec::new();
    if content.tool_calls {
        content_segments.extend(tool_events.iter().map(tool_event_metadata));
    }
    if content.images {
        content_segments.extend(
            images
                .iter()
                .enumerate()
                .map(|(position, image)| image_event_metadata(position, image)),
        );
    }
    json!({"content_segments": content_segments})
}

fn projected_provider_metadata(metadata: &Value, content: &HarnessUsageContentConfig) -> Value {
    let mut metadata = metadata.clone();
    let Some(object) = metadata.as_object_mut() else {
        return metadata;
    };

    // Provider event type lists are a raw structural view and can reveal that
    // a disabled tool or image category was present even after normalized
    // content segments are removed. Keep them only when every normalized
    // event content category is enabled.
    if !content.token_usage || !content.conversation_text || !content.tool_calls || !content.images
    {
        object.remove("provider_event_types");
    }
    if !content.tool_calls {
        object.remove("stop_reason");
    }

    metadata
}

fn image_event_metadata(position: usize, image: &ParsedImageAttachment) -> Value {
    json!({
        "type": "image",
        "position": position,
        "media_type": image.media_type,
        "byte_size": image.byte_size(),
        "sha256": image.sha256,
        "content_available": true,
    })
}

fn tool_event_metadata(event: &ParsedToolEvent) -> Value {
    match event {
        ParsedToolEvent::ToolCall {
            item_id,
            call_id,
            name,
            input,
        } => {
            json!({
                "type": "tool_call",
                "item_id": item_id,
                "call_id": call_id,
                "name": name,
                "input_sha256": sha256_hex(input),
                "input": input,
            })
        }
        ParsedToolEvent::ToolResult { call_id, output } => {
            json!({
                "type": "tool_result",
                "call_id": call_id,
                "output_sha256": sha256_hex(output),
                "output": output,
            })
        }
    }
}

fn usage_event(
    config: &HarnessUsageHookConfig,
    parts: &ParsedEventParts<'_>,
    side: EventSide<'_>,
    observed_at: DateTime<Utc>,
) -> NormalizedUsageEvent {
    let text_hash = sha256_hex(side.text);
    let content_hash = event_content_hash(&text_hash, side.attachments);
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
        turn_id: side.declared.turn_id.map(str::to_owned),
        naming_thread: side.declared.naming_thread,
        stream_id: side.declared.stream_id.map(str::to_owned),
        response_id: side.declared.response_id.map(str::to_owned),
        previous_response_id: side.declared.previous_response_id.map(str::to_owned),
        purpose: side.declared.purpose,
        // The title is model output, retained like the reply text.
        session_title: side
            .session_title
            .filter(|_| side.content.conversation_text)
            .map(str::to_owned),
        llm: LlmPayload {
            provider: parts.llm_provider.clone(),
            model: parts
                .llm_model
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
        },
        event_type: side.event_type,
        text: side.content.conversation_text.then(|| side.text.to_owned()),
        conversation: Some(retained_conversation(side.conversation, side.content)),
        token_usage: side.token_usage,
        metadata: side.metadata,
        attachments: normalized_image_attachments(side.attachments, side.content),
    }
}

fn event_content_hash(text_hash: &str, attachments: &[ParsedImageAttachment]) -> String {
    if attachments.is_empty() {
        return text_hash.to_owned();
    }
    let mut identity = String::from(text_hash);
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
        AgentEvent, ConversationMessage, EventPurpose, LlmProvider, MessageRole,
    };

    use crate::{
        config::{DeviceIdentity, HarnessUsageContentConfig, HarnessUsageHookConfig},
        harness::{AgentDeclaration, BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId},
        protocol::{
            anthropic::{
                AnthropicSessionIdSource, ParsedAnthropicMessagesExchange,
                claude_web::{ParsedClaudeWebExchange, conversation::ClaudeWebSessionIdSource},
            },
            model::{
                conversation::ConversationProjection,
                image::ParsedImageAttachment,
                tool::ParsedToolEvent,
                usage::{TokenUsage, TokenUsageSource},
            },
            openai::ParsedOpenAiExchange,
        },
    };

    use super::{normalize_exchange, retained_conversation};

    #[test]
    fn only_conversation_text_policy_omits_messages() {
        let mut source = ConversationProjection::empty();
        source.messages.push(ConversationMessage {
            id: None,
            role: MessageRole::User,
            text: "visible".to_owned(),
        });
        for conversation_text in [false, true] {
            for tool_calls in [false, true] {
                for images in [false, true] {
                    for token_usage in [false, true] {
                        let content = HarnessUsageContentConfig {
                            token_usage,
                            conversation_text,
                            tool_calls,
                            images,
                        };
                        let result = retained_conversation(&source, &content);
                        assert_eq!(result.messages.is_empty(), !conversation_text);
                        assert_eq!(result.policy_omitted, !conversation_text);
                    }
                }
            }
        }
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
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "codex"));
        assert!(
            events
                .iter()
                .all(|event| event.llm.provider == "gateway.example")
        );
        // Without a declared turn the events carry no turn identity.
        assert!(events.iter().all(|event| event.turn_id.is_none()));
        assert!(events.iter().all(|event| !event.naming_thread));
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
            session_id: Some("declared-session".to_owned()),
            turn_id: Some("turn-7".to_owned()),
            stream_id: Some("thread-7".to_owned()),
            naming_thread: true,
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
        );

        assert_eq!(events.len(), 2);
        for event in events {
            let event = AgentEvent::try_from(event).expect("event should convert");
            assert_eq!(event.session_id, "declared-session");
            assert_eq!(event.turn_id.as_deref(), Some("turn-7"));
            assert!(event.naming_thread);
            assert_eq!(event.stream_id.as_deref(), Some("thread-7"));
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
        );

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.text.is_none()));
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
        parsed.request_tool_events = vec![ParsedToolEvent::ToolResult {
            call_id: Some("call-1".to_owned()),
            output: "private tool output".to_owned(),
        }];
        parsed.response_tool_events = vec![ParsedToolEvent::ToolCall {
            item_id: None,
            call_id: Some("call-2".to_owned()),
            name: Some("shell".to_owned()),
            input: "private tool input".to_owned(),
        }];

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
            assert_eq!(events[0].get("tool_results").is_some(), retain_content);
            assert_eq!(events[1].get("tool_calls").is_some(), retain_content);
            assert_eq!(events[0].get("attachments").is_some(), retain_content);
            for event in &events {
                assert_eq!(event.get("text").is_some(), retain_content);
                assert_eq!(event["session_id"], "session-1");
                if !retain_content {
                    for field in ["tool_calls", "tool_results", "attachments", "metadata"] {
                        assert!(
                            event.get(field).is_none(),
                            "unexpected content field: {field}"
                        );
                    }
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
            request_conversation: ConversationProjection::empty(),
            response_conversation: ConversationProjection::empty(),
            request_texts: vec!["hello".to_owned()],
            request_images: Vec::new(),
            previous_response_id: None,
            request_tool_events: Vec::new(),
            response_tool_events: Vec::new(),
            response_texts: vec!["hi".to_owned()],
            usage: usage(),
            message_id: Some("msg-1".to_owned()),
            model: Some("claude-test".to_owned()),
            anthropic_version: Some("2023-06-01".to_owned()),
            event_types: vec!["message".to_owned()],
        }
    }

    #[test]
    fn session_title_rides_on_the_response_and_follows_the_text_policy() {
        let parsed = anthropic_messages_exchange();
        let declaration = AgentDeclaration {
            purpose: Some(EventPurpose::SessionTitle),
            session_title: Some("登录修复".to_owned()),
            ..AgentDeclaration::default()
        };
        let detection = detection(BuiltInHarness::ClaudeCode, "x-claude-code-session-id");

        for conversation_text in [true, false] {
            let content = HarnessUsageContentConfig {
                conversation_text,
                ..HarnessUsageContentConfig::default()
            };
            let events = normalize_exchange(
                &hook_config(),
                &parsed,
                &content,
                &detection,
                &LlmProvider::Anthropic,
                &declaration,
            );

            assert_eq!(events.len(), 2);
            assert!(
                events
                    .iter()
                    .all(|event| event.purpose == Some(EventPurpose::SessionTitle))
            );
            assert!(events[0].session_title.is_none());
            assert_eq!(
                events[1].session_title.as_deref(),
                conversation_text.then_some("登录修复")
            );
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
            request_conversation: ConversationProjection::empty(),
            response_conversation: ConversationProjection::empty(),
            request_texts: vec!["hello".to_owned()],
            request_images: Vec::new(),
            request_file_uuids: Vec::new(),
            protocol_turn_id: Some("assistant-message".to_owned()),
            request_tool_events: Vec::new(),
            response_tool_events: Vec::new(),
            response_texts: Vec::new(),
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
        );

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_type, "request");
        assert_eq!(events[0].metadata["agent_client"], "desktop");
        assert_eq!(events[0].metadata["path_kind"], "claude_web_completion");
    }

    #[test]
    fn tool_segments_convert_to_typed_plugin_activity() {
        let mut parsed = openai_exchange();
        parsed.response_tool_events = vec![ParsedToolEvent::ToolCall {
            item_id: Some("item-1".to_owned()),
            call_id: Some("call-1".to_owned()),
            name: Some("shell".to_owned()),
            input: "{\"command\":\"pwd\"}".to_owned(),
        }];

        let event = normalize_exchange(
            &hook_config(),
            &parsed,
            &HarnessUsageContentConfig::default(),
            &detection(BuiltInHarness::Codex, "x-openai-originator"),
            &LlmProvider::OpenAi,
            &AgentDeclaration::default(),
        )
        .pop()
        .expect("response event");
        let plugin_event = abyss_plugin_protocol::event::AgentEvent::try_from(event).unwrap();

        assert_eq!(plugin_event.tool_calls.len(), 1);
        assert_eq!(plugin_event.tool_calls[0].name, "shell");
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
            request_conversation: ConversationProjection::empty(),
            response_conversation: ConversationProjection::empty(),
            request_texts: vec!["hello".to_owned()],
            request_images: Vec::new(),
            response_texts: vec!["hi".to_owned()],
            usage: usage(),
            response_id: Some("response-1".to_owned()),
            previous_response_id: None,
            client_metadata: None,
            request_tool_events: Vec::new(),
            response_tool_events: Vec::new(),
            model: Some("model-test".to_owned()),
            event_types: vec!["response.completed".to_owned()],
        }
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
