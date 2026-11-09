//! Anthropic-family request and response content shared by its wire dialects.

use super::{
    conversation::{AnthropicRequest, AnthropicResponse},
    images::extract_anthropic_request_images,
    metadata::first_model,
    usage::best_usage,
};
use crate::protocol::{
    model::{
        request::{RequestContent, RequestMetadata},
        response::ResponseContent,
    },
    shared::json::event_types,
};
use serde_json::Value;

pub(in crate::protocol::anthropic) struct AnthropicContentParser;

impl AnthropicContentParser {
    pub(in crate::protocol::anthropic) fn parse_request(
        payload: Option<&Value>,
        truncated: bool,
    ) -> RequestContent {
        let conversation =
            AnthropicRequest::parse(payload.unwrap_or(&Value::Null), truncated).conversation();
        RequestContent {
            carries_messages: !conversation.entries.is_empty(),
            conversation,
            images: payload.map_or_else(Vec::new, extract_anthropic_request_images),
            metadata: RequestMetadata::parse(payload),
            usage: payload.and_then(|value| best_usage(std::slice::from_ref(value))),
            file_uuids: Vec::new(),
            assistant_message_uuid: None,
        }
    }

    pub(in crate::protocol::anthropic) fn parse_response(
        values: &[Value],
        incomplete: bool,
    ) -> ResponseContent {
        let response = AnthropicResponse::assemble(values, incomplete);
        let conversation = response.conversation();
        ResponseContent {
            has_content: !conversation.entries.is_empty(),
            conversation,
            usage: best_usage(values),
            model: first_model(values),
            response_id: response.id().map(str::to_owned),
            event_types: values.iter().flat_map(event_types).collect(),
        }
    }
}
