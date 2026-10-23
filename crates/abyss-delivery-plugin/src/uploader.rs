//! Translation, HTTP delivery, and plugin-owned failed-delivery persistence.

use std::{path::PathBuf, sync::Arc};

use abyss_sdk::plugin::{AgentEvent, ImageAttachment, TokenUsage};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    previous_response_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    subagent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    parent_subagent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    root_turn_id: Option<String>,
    llm: LlmPayload,
    event_type: String,
    token_usage: BackendTokenUsage,
    metadata: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    attachments: Vec<IngestImageAttachment>,
}

impl TryFrom<AgentEvent> for IngestUsageEvent {
    type Error = DeliveryPluginError;

    fn try_from(event: AgentEvent) -> Result<Self, Self::Error> {
        let mut metadata = json!({});
        if let Some(purpose) = event.purpose {
            metadata["purpose"] = serde_json::to_value(purpose)
                .map_err(|error| DeliveryPluginError::Translate(error.to_string()))?;
        }
        if !event.omitted.is_empty() {
            metadata["omitted"] = serde_json::to_value(&event.omitted)
                .map_err(|error| DeliveryPluginError::Translate(error.to_string()))?;
        }
        if let Some(conversation) = event.conversation {
            metadata["conversation"] = serde_json::to_value(conversation)
                .map_err(|error| DeliveryPluginError::Translate(error.to_string()))?;
        }
        // Headers are stored untouched; the backend reads nothing from them.
        if !event.headers.is_empty() {
            metadata["headers"] = serde_json::to_value(event.headers)
                .map_err(|error| DeliveryPluginError::Translate(error.to_string()))?;
        }
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
            response_id: event.response_id,
            previous_response_id: event.previous_response_id,
            subagent_id: event.subagent_id,
            parent_subagent_id: event.parent_subagent_id,
            root_turn_id: event.root_turn_id,
            llm: LlmPayload {
                provider: event.llm.provider.wire_name().to_owned(),
                model: event.llm.model,
            },
            event_type: event.side.wire_name().to_owned(),
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

#[cfg(test)]
mod tests {
    use abyss_sdk::plugin::{
        AgentContext, AgentEvent, AgentEventSide, DeviceContext, HttpHeader, HttpHeaderValue,
        LlmContext, LlmProvider, TokenUsage,
    };
    use serde_json::Value;

    use super::{IngestEventsRequest, SpoolRecord};

    #[test]
    fn uploads_tool_activity_only_inside_the_conversation() {
        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized = serde_json::to_value(request).expect("request should serialize");
        let ingest_event = &serialized["events"][0];

        assert!(ingest_event.get("text").is_none());
        assert!(ingest_event["metadata"].get("content_segments").is_none());
        assert_eq!(
            ingest_event["metadata"]["conversation"]["entries"][2]["role"],
            "tool_call"
        );
        assert_eq!(serialized["diagnostic_captures"], serde_json::json!([]));
    }

    #[test]
    fn sends_the_declared_ids_as_top_level_fields() {
        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized = serde_json::to_value(request).expect("request should serialize");
        let ingest_event = &serialized["events"][0];

        assert_eq!(ingest_event["subagent_id"], "agent-2");
        assert_eq!(ingest_event["parent_subagent_id"], "agent-1");
        assert_eq!(ingest_event["root_turn_id"], "turn-1");
        for field in ["subagent_id", "parent_subagent_id", "root_turn_id"] {
            assert!(ingest_event["metadata"].get(field).is_none(), "{field}");
        }
    }

    #[test]
    fn stores_the_conversation_as_backend_metadata() {
        let event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized = serde_json::to_value(request).expect("request should serialize");
        let metadata = &serialized["events"][0]["metadata"];

        let roles = metadata["conversation"]["entries"]
            .as_array()
            .expect("entries should be an array")
            .iter()
            .map(|entry| entry["role"].as_str().expect("role should be a string"))
            .collect::<Vec<_>>();
        assert_eq!(roles, ["reasoning", "assistant", "tool_call"]);
        assert!(metadata.get("omitted").is_none());
    }

    #[test]
    fn stores_the_omitted_categories_as_backend_metadata() {
        let mut event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        event.omitted = vec![
            abyss_sdk::plugin::ContentCategory::ConversationText,
            abyss_sdk::plugin::ContentCategory::Images,
        ];
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized = serde_json::to_value(request).expect("request should serialize");

        assert_eq!(
            serialized["events"][0]["metadata"]["omitted"],
            serde_json::json!(["conversation_text", "images"])
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
        let legacy_event = request["events"][0]
            .as_object_mut()
            .expect("event should be an object");
        legacy_event.remove("attachments");
        // Older spools also carry the collector-counted turn number.
        legacy_event.insert("turn_index".to_owned(), 3_u32.into());
        // And the retired event text.
        legacy_event.insert("text".to_owned(), "hello".into());
        let legacy_record = serde_json::json!({
            "reason": "delivery destination returned HTTP 401 Unauthorized",
            "request": request,
        });

        let record: SpoolRecord =
            serde_json::from_value(legacy_record).expect("legacy spool record should decode");
        let serialized = serde_json::to_value(record).expect("record should serialize");

        assert!(serialized["request"]["events"][0]["attachments"].is_null());
        assert!(
            serialized["request"]["events"][0]
                .get("turn_index")
                .is_none()
        );
        assert!(serialized["request"]["events"][0].get("text").is_none());
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
            response_id: Some("resp-1".to_owned()),
            previous_response_id: None,
            subagent_id: None,
            parent_subagent_id: None,
            root_turn_id: None,
            purpose: None,
            llm: LlmContext {
                provider: LlmProvider::OpenAi,
                model: "gpt".to_owned(),
            },
            side: AgentEventSide::Request,
            omitted: Vec::new(),
            conversation: None,
            headers: vec![HttpHeader {
                name: "request-id".to_owned(),
                value: HttpHeaderValue::Text("req_1".to_owned()),
            }],
            token_usage: TokenUsage {
                input_tokens: 1,
                output_tokens: 0,
                cache_read_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                total_tokens: 1,
            },
            attachments: Vec::new(),
        };
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized: Value = serde_json::to_value(request).expect("request should serialize");

        assert_eq!(serialized["events"][0]["event_type"], "request");
        assert!(serialized["events"][0].get("text").is_none());
        assert!(
            serialized["events"][0]["metadata"]
                .get("content_segments")
                .is_none()
        );
        assert_eq!(serialized["events"][0]["response_id"], "resp-1");
        assert!(
            serialized["events"][0]
                .get("previous_response_id")
                .is_none()
        );
        for field in ["subagent_id", "parent_subagent_id", "root_turn_id"] {
            assert!(
                serialized["events"][0].get(field).is_none(),
                "an undeclared {field} is omitted"
            );
        }
        assert!(serialized["events"][0]["metadata"].get("turn_id").is_none());
        assert!(serialized["events"][0].get("turn_index").is_none());
        assert_eq!(
            serialized["events"][0]["metadata"]["headers"],
            serde_json::json!([{"name": "request-id", "value": "req_1"}])
        );
    }

    #[test]
    fn carries_exchange_placement() {
        let mut event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        event.agent.name = "claude-code".to_owned();

        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized: Value = serde_json::to_value(request).expect("request should serialize");
        let ingest_event = &serialized["events"][0];
        let metadata = &ingest_event["metadata"];

        assert!(ingest_event.get("turn_id").is_none());
        assert!(ingest_event.get("stream_id").is_none());
        assert_eq!(ingest_event["response_id"], "resp-123");
        assert_eq!(ingest_event["previous_response_id"], "resp-122");
        assert!(metadata.get("claude_turn_id").is_none());
        assert!(metadata.get("claude_code_billing").is_none());
        assert!(metadata.get("claude_thread").is_none());
        assert!(
            metadata["conversation"]
                .get("previous_response_id")
                .is_none()
        );
        assert_eq!(metadata["purpose"], "session_title");
        assert!(metadata.get("session_title").is_none());
    }

    #[test]
    fn retains_prewarm_purpose_and_observed_usage_for_backend_accounting() {
        let mut event: AgentEvent = serde_json::from_str(include_str!(
            "../../../specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
        ))
        .expect("fixture should decode");
        event.purpose = Some(abyss_sdk::plugin::EventPurpose::Prewarm);
        let expected_usage = serde_json::to_value(&event.token_usage).unwrap();
        let request = IngestEventsRequest::try_from(event).expect("event should translate");
        let serialized = serde_json::to_value(request).unwrap();
        assert_eq!(serialized["events"][0]["metadata"]["purpose"], "prewarm");
        assert_eq!(serialized["events"][0]["token_usage"], expected_usage);
    }
}
