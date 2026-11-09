//! Chat Completions request and response projections, independent of transport and observation.

use super::{request::ChatRequest, response::ChatResponse};
use crate::protocol::{
    LlmProtocol, OpenAiProtocol,
    model::{
        request::{RequestContent, RequestMetadata},
        response::ResponseContent,
    },
    openai::shared::{
        images::extract_openai_request_images,
        metadata::{first_model, response_id},
        usage::best_usage,
    },
    parser::ProtocolParser,
    shared::json::event_types,
};
use serde_json::Value;

pub struct ChatCompletionsParser;

impl ProtocolParser for ChatCompletionsParser {
    const PROTOCOL: LlmProtocol = LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions);

    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent {
        let parsed = ChatRequest::parse(payload, truncated);
        let conversation = parsed.conversation();
        RequestContent {
            carries_messages: !conversation.entries.is_empty(),
            conversation,
            images: payload.map_or_else(Vec::new, extract_openai_request_images),
            metadata: RequestMetadata::parse(payload),
            usage: payload.and_then(|value| best_usage(std::slice::from_ref(value))),
            file_uuids: Vec::new(),
            assistant_message_uuid: None,
        }
    }

    fn parse_response(values: &[Value], incomplete: bool) -> ResponseContent {
        let parsed = ChatResponse::assemble(values, incomplete);
        ResponseContent {
            has_content: !parsed.is_empty(),
            conversation: parsed.conversation(),
            usage: best_usage(values),
            model: first_model(values),
            response_id: response_id(values),
            event_types: values.iter().flat_map(event_types).collect(),
        }
    }
}
