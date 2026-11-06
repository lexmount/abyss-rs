//! Chat Completions HTTP content parsing; common capture metadata is assembled separately.

use abyss_mitm::HttpExchange;

use super::response::ChatResponse;
use crate::protocol::openai::shared::{exchange::ParsedOpenAiExchange, http::OpenAiHttpExchange};
use crate::protocol::{LlmProtocol, OpenAiProtocol, request::RequestContent};

/// Parses a Chat Completions exchange selected by protocol detection.
#[must_use]
pub fn parse_chat_completions_exchange(exchange: &HttpExchange) -> Option<ParsedOpenAiExchange> {
    let payload = exchange.request.body().json();
    let request = RequestContent::parse(
        LlmProtocol::OpenAi(OpenAiProtocol::ChatCompletions),
        payload,
        exchange.request.body().truncated(),
    );
    let decoded = OpenAiHttpExchange::decode(exchange);
    let response = ChatResponse::assemble(&decoded.documents.values, decoded.documents.incomplete);
    decoded.finish(request, &response)
}
