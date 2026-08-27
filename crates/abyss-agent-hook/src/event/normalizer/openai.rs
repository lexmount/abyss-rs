//! OpenAI-family parsed exchange adaptation for the common event normalizer.

use abyss_plugin_protocol::event::LlmProvider;
use serde_json::json;

use crate::{
    config::HarnessUsageContentConfig,
    correlation::CorrelationContext,
    harness::HarnessDetection,
    protocol::{model::usage::TokenUsageSource, openai::ParsedOpenAiExchange},
};

use super::{
    HttpMetadata, NormalizableExchange, ParsedEventParts, content_segments_metadata, harness_client,
};

impl NormalizableExchange for ParsedOpenAiExchange {
    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn protocol_turn_id(&self) -> Option<&str> {
        self.protocol_turn_id.as_deref()
    }

    fn event_parts(
        &self,
        content: &HarnessUsageContentConfig,
        detection: &HarnessDetection,
        provider: &LlmProvider,
        correlation: &CorrelationContext,
    ) -> ParsedEventParts<'_> {
        ParsedEventParts {
            http: HttpMetadata {
                transport: self.transport,
                host: &self.host,
                path: &self.path,
                method: &self.method,
            },
            harness_name: detection.harness_id.to_string(),
            harness_client: harness_client(detection),
            harness_version: detection.version.clone(),
            llm_provider: provider.wire_name().to_owned(),
            llm_model: self.model.clone(),
            session_id: correlation.session_id.clone(),
            response_identity: self
                .response_id
                .clone()
                .unwrap_or_else(|| self.request_hash.clone()),
            request_text: self.request_texts.join("\n\n"),
            request_images: self.request_images.clone(),
            response_text: self.response_texts.join("\n\n"),
            usage: self.usage.clone(),
            usage_source: TokenUsageSource::provider_or_absent(&self.usage),
            metadata: json!({
                "response_id": self.response_id,
                "previous_response_id": self.previous_response_id,
                "protocol_turn_id": self.protocol_turn_id,
                "turn_identity_source": if self.protocol_turn_id.is_some() {
                    "protocol_turn_id"
                } else {
                    "collector_sequence"
                },
                "provider_call_index": correlation.provider_call_index,
                "request_hash": self.request_hash,
                "source_evidence": detection.evidence_names(),
                "working_directory": detection.working_directory,
                "provider_event_types": self.event_types,
            }),
            request_metadata: content_segments_metadata(
                &self.request_tool_events,
                &self.request_images,
                content,
            ),
            response_metadata: content_segments_metadata(&self.response_tool_events, &[], content),
            request_has_structured_content: !self.request_tool_events.is_empty()
                || !self.request_images.is_empty(),
            response_has_structured_content: !self.response_tool_events.is_empty(),
            allow_request_without_response: false,
        }
    }
}
