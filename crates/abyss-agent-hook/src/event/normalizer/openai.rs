//! OpenAI-family parsed exchange adaptation for the common event normalizer.

use abyss_plugin_protocol::event::{EventPurpose, LlmProvider};

use crate::{harness::HarnessDetection, protocol::openai::ParsedOpenAiExchange};

use super::{Continuation, NormalizableExchange, ParsedEventParts};

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
            harness_name: detection.harness_id.to_string(),
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
            allow_request_without_response: false,
        }
    }
}
