//! Translation, HTTP delivery, and plugin-owned failed-delivery persistence.

use std::{path::PathBuf, sync::Arc};

use abyss_sdk::plugin::{AgentEvent, ImageAttachment, TokenUsage, ToolCall, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::{
    fs::{self, OpenOptions},
    io::AsyncWriteExt as _,
    sync::Mutex,
};

use crate::{
    authentication::DeliveryAuthenticationManager, config::DeliveryPluginConfig,
    error::DeliveryPluginError,
};

/// Official HTTP destination implementation for broker Agent events.
pub struct EventUploader {
    client: reqwest::Client,
    endpoint: String,
    spool_enabled: bool,
    spool_path: PathBuf,
    authentication: Arc<DeliveryAuthenticationManager>,
    delivery_lock: Mutex<()>,
}

/// Result of one failed-event spool replay attempt.
#[derive(Serialize)]
pub struct ReplaySummary {
    /// Number of records accepted by the destination.
    pub replayed: usize,
    /// Number of records retained for a later replay.
    pub remaining: usize,
}

impl EventUploader {
    /// Creates an uploader from product-owned plugin configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be initialized.
    pub fn new(
        config: &DeliveryPluginConfig,
        authentication: Arc<DeliveryAuthenticationManager>,
    ) -> Result<Self, DeliveryPluginError> {
        let client = reqwest::Client::builder()
            .no_proxy()
            .build()
            .map_err(|error| DeliveryPluginError::Request(error.to_string()))?;
        Ok(Self {
            client,
            endpoint: config.delivery.endpoint.clone(),
            spool_enabled: config.delivery.spool_enabled,
            spool_path: config.spool_path(),
            authentication,
            delivery_lock: Mutex::new(()),
        })
    }

    /// Delivers one event, accepting responsibility through the spool on failure.
    ///
    /// # Errors
    ///
    /// Returns an error when the event cannot be translated, delivery fails
    /// while persistence is disabled, or the failed-delivery spool cannot be written.
    pub async fn deliver(&self, event: AgentEvent) -> Result<(), DeliveryPluginError> {
        let request = IngestEventsRequest::try_from(event)?;
        let _guard = self.delivery_lock.lock().await;
        if let Err(error) = self.post(&request).await {
            if self.spool_enabled {
                self.spool(&request, &error.to_string()).await?;
                return Ok(());
            }
            return Err(error);
        }
        Ok(())
    }

    /// Replays durable failed events using the current authentication snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when spool contents cannot be read, decoded, or
    /// rewritten. A destination failure retains the failed record and all
    /// later records without failing the worker.
    pub async fn replay_spool(&self) -> Result<ReplaySummary, DeliveryPluginError> {
        let _guard = self.delivery_lock.lock().await;
        self.replay_spool_locked().await
    }

    /// Installs product-managed authentication and replays durable failures as
    /// one operation serialized with destination requests.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential is invalid or spool replay fails.
    pub async fn set_managed_bearer_and_replay(
        &self,
        bearer_token: &str,
        audience: &str,
    ) -> Result<ReplaySummary, DeliveryPluginError> {
        let _guard = self.delivery_lock.lock().await;
        self.authentication
            .set_managed_bearer(bearer_token, audience)
            .await?;
        self.replay_spool_locked().await
    }

    /// Clears product-managed authentication after any in-flight destination
    /// request has completed.
    ///
    /// # Errors
    ///
    /// Returns an error when managed authentication is not configured.
    pub async fn clear_managed_bearer(&self) -> Result<(), DeliveryPluginError> {
        let _guard = self.delivery_lock.lock().await;
        self.authentication.clear_managed_bearer().await
    }

    async fn replay_spool_locked(&self) -> Result<ReplaySummary, DeliveryPluginError> {
        let body = match fs::read(&self.spool_path).await {
            Ok(body) => body,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ReplaySummary {
                    replayed: 0,
                    remaining: 0,
                });
            }
            Err(source) => return Err(self.spool_error(source.to_string())),
        };
        let mut records = Vec::new();
        for line in body
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            records.push(
                serde_json::from_slice::<SpoolRecord>(line)
                    .map_err(|source| self.spool_error(source.to_string()))?,
            );
        }

        let mut replayed = 0_usize;
        for record in &records {
            if self.post(&record.request).await.is_err() {
                break;
            }
            replayed = replayed.saturating_add(1);
        }
        let remaining = records.split_off(replayed);
        self.replace_spool(&remaining).await?;
        Ok(ReplaySummary {
            replayed,
            remaining: remaining.len(),
        })
    }

    /// Counts durable failed-event records for product-facing status.
    ///
    /// # Errors
    ///
    /// Returns an error when the spool cannot be read.
    pub async fn spooled_event_count(&self) -> Result<usize, DeliveryPluginError> {
        let _guard = self.delivery_lock.lock().await;
        match fs::read(&self.spool_path).await {
            Ok(body) => Ok(body
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .count()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(source) => Err(self.spool_error(source.to_string())),
        }
    }

    /// Returns the configured remote endpoint without any credential material.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    async fn post(&self, request: &IngestEventsRequest) -> Result<(), DeliveryPluginError> {
        let authentication = self
            .authentication
            .for_request()
            .await
            .ok_or(DeliveryPluginError::AuthenticationUnavailable)?;
        let mut builder = self
            .client
            .post(&self.endpoint)
            .header("accept", "application/json")
            .header("user-agent", "abyss-delivery-plugin/0.1");
        if let Some(value) = authentication.authorization_header() {
            builder = builder.header(reqwest::header::AUTHORIZATION, value);
        }
        if let Some(value) = authentication.cookie_header() {
            builder = builder.header(reqwest::header::COOKIE, value);
        }

        let response = builder
            .json(request)
            .send()
            .await
            .map_err(|error| DeliveryPluginError::Request(error.without_url().to_string()))?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            self.authentication.mark_unauthorized().await;
        }
        if !status.is_success() {
            return Err(DeliveryPluginError::HttpStatus(status));
        }
        let response = response
            .json::<IngestEventsResponse>()
            .await
            .map_err(|error| DeliveryPluginError::Response(error.without_url().to_string()))?;
        if response.rejected > 0 || !response.errors.is_empty() {
            return Err(DeliveryPluginError::Rejected {
                rejected: response.rejected,
                errors: response.errors,
            });
        }
        Ok(())
    }

    async fn spool(
        &self,
        request: &IngestEventsRequest,
        reason: &str,
    ) -> Result<(), DeliveryPluginError> {
        if let Some(parent) = self.spool_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|source| self.spool_error(source.to_string()))?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.spool_path)
            .await
            .map_err(|source| self.spool_error(source.to_string()))?;
        let mut line = serde_json::to_vec(&SpoolRecord {
            reason: reason.to_owned(),
            request: request.clone(),
        })
        .map_err(|source| self.spool_error(source.to_string()))?;
        line.push(b'\n');
        file.write_all(&line)
            .await
            .map_err(|source| self.spool_error(source.to_string()))?;
        file.flush()
            .await
            .map_err(|source| self.spool_error(source.to_string()))?;
        Ok(())
    }

    async fn replace_spool(&self, records: &[SpoolRecord]) -> Result<(), DeliveryPluginError> {
        if records.is_empty() {
            return match fs::remove_file(&self.spool_path).await {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(self.spool_error(source.to_string())),
            };
        }
        let parent = self
            .spool_path
            .parent()
            .ok_or_else(|| self.spool_error("spool path has no parent directory".to_owned()))?;
        fs::create_dir_all(parent)
            .await
            .map_err(|source| self.spool_error(source.to_string()))?;
        let temporary = self
            .spool_path
            .with_extension(format!("tmp.{}", std::process::id()));
        let mut options = fs::OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            options.mode(0o600);
        }
        let result = async {
            let mut file = options
                .open(&temporary)
                .await
                .map_err(|source| self.spool_error(source.to_string()))?;
            for record in records {
                let mut line = serde_json::to_vec(record)
                    .map_err(|source| self.spool_error(source.to_string()))?;
                line.push(b'\n');
                file.write_all(&line)
                    .await
                    .map_err(|source| self.spool_error(source.to_string()))?;
            }
            file.flush()
                .await
                .map_err(|source| self.spool_error(source.to_string()))?;
            drop(file);
            Self::replace_file(&temporary, &self.spool_path)
                .await
                .map_err(|source| self.spool_error(source.to_string()))
        }
        .await;
        if result.is_err() {
            drop(fs::remove_file(&temporary).await);
        }
        result
    }

    async fn replace_file(
        temporary: &std::path::Path,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        match fs::rename(temporary, path).await {
            Ok(()) => Ok(()),
            #[cfg(windows)]
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(path).await?;
                fs::rename(temporary, path).await
            }
            Err(error) => Err(error),
        }
    }

    fn spool_error(&self, detail: String) -> DeliveryPluginError {
        DeliveryPluginError::Spool {
            path: self.spool_path.clone(),
            detail,
        }
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct IngestEventsRequest {
    events: Vec<IngestUsageEvent>,
    diagnostic_captures: Vec<Value>,
}

impl TryFrom<AgentEvent> for IngestEventsRequest {
    type Error = DeliveryPluginError;

    fn try_from(event: AgentEvent) -> Result<Self, Self::Error> {
        Ok(Self {
            events: vec![IngestUsageEvent::try_from(event)?],
            diagnostic_captures: Vec::new(),
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct IngestUsageEvent {
    event_id: String,
    observed_at: String,
    device: DevicePayload,
    agent: AgentPayload,
    session_id: String,
    turn_index: i32,
    llm: LlmPayload,
    event_type: String,
    text: Option<String>,
    token_usage: BackendTokenUsage,
    metadata: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<IngestImageAttachment>,
}

impl TryFrom<AgentEvent> for IngestUsageEvent {
    type Error = DeliveryPluginError;

    fn try_from(event: AgentEvent) -> Result<Self, Self::Error> {
        let turn_index = i32::try_from(event.turn_index.get()).map_err(|_| {
            DeliveryPluginError::Translate("turn_index exceeds backend range".to_owned())
        })?;
        let metadata = tool_activity_metadata(event.tool_calls, event.tool_results);
        Ok(Self {
            event_id: event.event_id,
            observed_at: event.occurred_at.to_rfc3339(),
            device: DevicePayload {
                host_name: event.device.host_name,
                platform: event.device.platform,
                os_version: event.device.os_version,
            },
            agent: AgentPayload {
                name: event.agent.name,
                version: event.agent.version,
            },
            session_id: event.session_id,
            turn_index,
            llm: LlmPayload {
                provider: event.llm.provider.wire_name().to_owned(),
                model: event.llm.model,
            },
            event_type: event.side.wire_name().to_owned(),
            text: event.text,
            token_usage: BackendTokenUsage::try_from(event.token_usage)?,
            metadata,
            attachments: event
                .attachments
                .into_iter()
                .map(IngestImageAttachment::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct DevicePayload {
    host_name: String,
    platform: String,
    os_version: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct AgentPayload {
    name: String,
    version: Option<String>,
}

#[derive(Clone, Deserialize, Serialize)]
struct LlmPayload {
    provider: String,
    model: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "the backend contract uses explicit token counter names"
)]
struct BackendTokenUsage {
    input_tokens: i64,
    output_tokens: i64,
    cache_read_tokens: i64,
    cache_write_tokens: i64,
    reasoning_tokens: i64,
    total_tokens: i64,
}

impl TryFrom<TokenUsage> for BackendTokenUsage {
    type Error = DeliveryPluginError;

    fn try_from(usage: TokenUsage) -> Result<Self, Self::Error> {
        Ok(Self {
            input_tokens: token_counter("input_tokens", usage.input_tokens)?,
            output_tokens: token_counter("output_tokens", usage.output_tokens)?,
            cache_read_tokens: token_counter("cache_read_tokens", usage.cache_read_tokens)?,
            cache_write_tokens: token_counter("cache_write_tokens", usage.cache_write_tokens)?,
            reasoning_tokens: token_counter("reasoning_tokens", usage.reasoning_tokens)?,
            total_tokens: token_counter("total_tokens", usage.total_tokens)?,
        })
    }
}

#[derive(Clone, Deserialize, Serialize)]
struct IngestImageAttachment {
    position: i32,
    media_type: String,
    byte_size: u64,
    sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_base64: Option<String>,
}

impl TryFrom<ImageAttachment> for IngestImageAttachment {
    type Error = DeliveryPluginError;

    fn try_from(attachment: ImageAttachment) -> Result<Self, Self::Error> {
        Ok(Self {
            position: i32::try_from(attachment.position).map_err(|_| {
                DeliveryPluginError::Translate(
                    "image attachment position exceeds backend range".to_owned(),
                )
            })?,
            media_type: attachment.media_type.wire_name().to_owned(),
            byte_size: attachment.byte_size,
            sha256: attachment.sha256,
            content_base64: attachment.content_base64,
        })
    }
}

#[derive(Deserialize)]
struct IngestEventsResponse {
    rejected: usize,
    #[serde(default)]
    errors: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct SpoolRecord {
    reason: String,
    request: IngestEventsRequest,
}

fn token_counter(name: &str, value: u64) -> Result<i64, DeliveryPluginError> {
    i64::try_from(value).map_err(|_| {
        DeliveryPluginError::Translate(format!("{name} exceeds backend counter range"))
    })
}

fn tool_activity_metadata(tool_calls: Vec<ToolCall>, tool_results: Vec<ToolResult>) -> Value {
    let capacity = tool_calls.len().saturating_add(tool_results.len());
    let mut segments = Vec::with_capacity(capacity);
    segments.extend(tool_calls.into_iter().map(|call| {
        json!({
            "type": "tool_call",
            "call_id": call.call_id,
            "name": call.name,
            "input": call.input,
            "input_sha256": call.input_sha256,
        })
    }));
    segments.extend(tool_results.into_iter().map(|result| {
        json!({
            "type": "tool_result",
            "call_id": result.call_id,
            "output": result.output,
            "output_sha256": result.output_sha256,
        })
    }));
    if segments.is_empty() {
        json!({})
    } else {
        json!({"content_segments": segments})
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroU32;

    use abyss_sdk::plugin::{
        AgentContext, AgentEvent, AgentEventSide, DeviceContext, LlmContext, LlmProvider,
        TokenUsage, ToolCall,
    };
    use serde_json::Value;

    use super::{IngestEventsRequest, SpoolRecord};

    #[test]
    fn translates_public_tool_types_into_backend_metadata() {
        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized = serde_json::to_value(request).expect("request should serialize");

        assert_eq!(
            serialized["events"][0]["metadata"]["content_segments"][0]["type"],
            "tool_call"
        );
        assert!(
            serialized["diagnostic_captures"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn reads_spooled_events_written_before_attachments_were_added() {
        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let mut request = serde_json::to_value(request).expect("request should serialize");
        request["events"][0]
            .as_object_mut()
            .expect("event should be an object")
            .remove("attachments");
        let legacy_record = serde_json::json!({
            "reason": "delivery destination returned HTTP 401 Unauthorized",
            "request": request,
        });

        let record: SpoolRecord =
            serde_json::from_value(legacy_record).expect("legacy spool record should decode");
        let serialized = serde_json::to_value(record).expect("record should serialize");

        assert!(serialized["request"]["events"][0]["attachments"].is_null());
    }

    #[test]
    fn keeps_the_backend_envelope_inside_the_delivery_plugin() {
        let event = AgentEvent {
            event_id: "event-1".to_owned(),
            occurred_at: chrono::Utc::now(),
            device: DeviceContext {
                host_name: "host".to_owned(),
                platform: "linux".to_owned(),
                os_version: None,
            },
            agent: AgentContext {
                name: "codex".to_owned(),
                version: None,
            },
            session_id: "session".to_owned(),
            turn_index: NonZeroU32::new(1).unwrap(),
            llm: LlmContext {
                provider: LlmProvider::OpenAi,
                model: "gpt".to_owned(),
            },
            side: AgentEventSide::Request,
            text: None,
            token_usage: TokenUsage {
                input_tokens: 1,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: 1,
            },
            tool_calls: vec![ToolCall {
                call_id: "call-1".to_owned(),
                name: "exec".to_owned(),
                input: "pwd".to_owned(),
                input_sha256: "hash".to_owned(),
            }],
            tool_results: Vec::new(),
            attachments: Vec::new(),
        };
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized: Value = serde_json::to_value(request).expect("request should serialize");

        assert_eq!(serialized["events"][0]["event_type"], "request");
        assert_eq!(
            serialized["events"][0]["metadata"]["content_segments"][0]["name"],
            "exec"
        );
    }
}
