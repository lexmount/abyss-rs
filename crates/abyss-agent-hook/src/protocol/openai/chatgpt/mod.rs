//! Desktop `ChatGPT` conversation HTTP operations and their shared parser stages.

mod message;
mod response;

use abyss_mitm::{FlowContext, HttpExchange};
use abyss_plugin_protocol::event::EntryRole;
use http::{Method, Request};
use serde_json::Value;

use super::shared::{exchange::ParsedOpenAiExchange, http::OpenAiHttpExchange};
use crate::protocol::{
    LlmProtocol, OpenAiProtocol,
    model::{
        conversation::ConversationProjection,
        request::{RequestContent, RequestMetadata},
        response::{ResponseContent, ResponseInput},
    },
    parser::{ProtocolParser, parse_http_exchange},
    shared::{
        http::{flow_server_name, request_host},
        json::string_field,
    },
};

pub fn matches_request<B>(flow: &FlowContext, request: &Request<B>) -> bool {
    let path = request.uri().path();
    request.method() == Method::POST
        && matches!(
            path.trim_end_matches('/'),
            "/backend-api/f/conversation" | "/backend-api/conversation"
        )
        && matches!(
            request_host(request.headers(), request.uri())
                .or_else(|| flow_server_name(flow))
                .as_deref(),
            Some("chatgpt.com" | "chat.openai.com")
        )
}

pub struct ChatGptParser;
impl ProtocolParser for ChatGptParser {
    const PROTOCOL: LlmProtocol = LlmProtocol::OpenAi(OpenAiProtocol::ChatGptConversation);

    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent {
        let messages = payload.and_then(|v| v.get("messages")?.as_array());
        let entries = messages
            .into_iter()
            .flatten()
            .filter_map(|message| message::entry(message, EntryRole::User))
            .collect();
        let conversation = ConversationProjection::from_entries(
            entries,
            ConversationProjection::completeness(messages.is_some(), truncated),
        );
        let mut metadata = RequestMetadata::parse(payload);
        metadata.previous_response_id = payload
            .filter(|v| string_field(v, "conversation_id").is_some())
            .and_then(|v| string_field(v, "parent_message_id"))
            .map(str::to_owned);
        RequestContent {
            carries_messages: !conversation.entries.is_empty(),
            conversation,
            metadata,
            images: Vec::new(),
            file_uuids: Vec::new(),
            assistant_message_uuid: None,
            usage: None,
        }
    }

    fn parse_response(input: ResponseInput<'_>) -> ResponseContent {
        response::assemble(&input)
    }
}

pub(super) fn parse_exchange(exchange: &HttpExchange) -> Option<ParsedOpenAiExchange> {
    parse_http_exchange::<ChatGptParser, _, _>(exchange, |exchange, request, mut response| {
        if response.session_id.is_none() {
            response.session_id = exchange
                .request
                .body()
                .json()
                .and_then(|v| string_field(v, "conversation_id"))
                .map(str::to_owned);
        }
        OpenAiHttpExchange::assemble_exchange(exchange, request, response)
    })
}

#[cfg(test)]
mod tests;
