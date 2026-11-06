//! Shared request content extraction used by live inspection and exchange observers.

use abyss_plugin_protocol::event::Conversation;
use serde_json::Value;

use super::{
    AnthropicProtocol, LlmProtocol, OpenAiProtocol,
    anthropic::shared::{conversation::AnthropicRequest, images::extract_anthropic_request_images},
    model::image::ParsedImageAttachment,
    openai::{
        chat_completions::request::ChatRequest, responses::request::ResponsesRequest,
        shared::images::extract_openai_request_images,
    },
};

pub struct RequestContent<'a> {
    pub conversation: Conversation,
    pub images: Vec<ParsedImageAttachment>,
    pub metadata: RequestMetadata<'a>,
    carries_messages: bool,
}

/// Borrow metadata so observation need not copy unused tool schemas.
pub struct RequestMetadata<'a> {
    pub model: Option<&'a str>,
    pub tool_definitions: Option<&'a Value>,
    pub previous_response_id: Option<&'a str>,
    pub client_metadata: Option<&'a Value>,
}

impl<'a> RequestMetadata<'a> {
    fn parse(protocol: LlmProtocol, payload: Option<&'a Value>) -> Self {
        let previous_response_id = payload
            .and_then(|value| match protocol {
                LlmProtocol::Anthropic(AnthropicProtocol::Messages) => value
                    .get("thread")
                    .filter(|thread| thread.get("type").and_then(Value::as_str) == Some("continue"))
                    .and_then(|thread| thread.get("previous_message_id")),
                _ => value.get("previous_response_id"),
            })
            .and_then(Value::as_str);
        Self {
            model: payload
                .and_then(|value| value.get("model"))
                .and_then(Value::as_str),
            tool_definitions: payload.and_then(|value| value.get("tools")),
            previous_response_id,
            client_metadata: payload.and_then(|value| value.get("client_metadata")),
        }
    }
}

impl<'a> RequestContent<'a> {
    pub fn parse(protocol: LlmProtocol, payload: Option<&'a Value>, truncated: bool) -> Self {
        let metadata = RequestMetadata::parse(protocol, payload);
        match protocol {
            LlmProtocol::OpenAi(OpenAiProtocol::Responses) => {
                let request = ResponsesRequest::parse(payload, truncated);
                Self {
                    metadata,
                    carries_messages: !request.is_empty(),
                    conversation: request.conversation(),
                    images: payload.map_or_else(Vec::new, extract_openai_request_images),
                }
            }
            LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions) => {
                let conversation = ChatRequest::parse(payload, truncated).conversation();
                Self {
                    metadata,
                    carries_messages: !conversation.entries.is_empty(),
                    conversation,
                    images: payload.map_or_else(Vec::new, extract_openai_request_images),
                }
            }
            LlmProtocol::Anthropic(
                AnthropicProtocol::Messages | AnthropicProtocol::ClaudeWeb(_),
            ) => {
                let payload = payload.unwrap_or(&Value::Null);
                let conversation = AnthropicRequest::parse(payload, truncated).conversation();
                Self {
                    metadata,
                    carries_messages: !conversation.entries.is_empty(),
                    conversation,
                    images: extract_anthropic_request_images(payload),
                }
            }
        }
    }

    pub const fn is_empty(&self) -> bool {
        !self.carries_messages
    }
}
