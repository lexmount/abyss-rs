//! OpenAI-family parsed exchange adaptation for the common event normalizer.

use abyss_plugin_protocol::event::{EventPurpose, LlmProvider};
use serde_json::json;

use crate::{
    harness::HarnessDetection,
    protocol::{model::usage::TokenUsageSource, openai::ParsedOpenAiExchange},
};

use super::{Continuation, HttpMetadata, NormalizableExchange, ParsedEventParts, harness_client};

impl NormalizableExchange for ParsedOpenAiExchange {
    fn purpose(&self) -> Option<EventPurpose> {
        (self.generates_output == Some(false)).then_some(EventPurpose::Prewarm)
    }

    fn session_id(&self) -> &str {
        &self.session_id
    }

    fn continuation(&self) -> Continuation<'_> {
        Continuation {
            response_id: self.response_id.as_deref(),
            previous_response_id: self.previous_response_id.as_deref(),
        }
    }

    fn event_parts(
        &self,
        detection: &HarnessDetection,
        provider: &LlmProvider,
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
            session_id: self.session_id().to_owned(),
            response_identity: self
                .response_id
                .clone()
                .unwrap_or_else(|| self.request_hash.clone()),
            request_conversation: &self.request_conversation,
            response_conversation: &self.response_conversation,
            request_images: self.request_images.clone(),
            usage: self.usage.clone(),
            usage_source: TokenUsageSource::provider_or_absent(&self.usage),
            metadata: json!({
                "response_id": self.response_id,
                "previous_response_id": self.previous_response_id,
                "request_hash": self.request_hash,
                "source_evidence": detection.evidence_names(),
                "working_directory": detection.working_directory,
                "provider_event_types": self.event_types,
            }),
            allow_request_without_response: false,
        }
    }
}
