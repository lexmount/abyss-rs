//! Responses HTTP content parsing; common capture metadata is assembled separately.

use abyss_mitm::HttpExchange;

use super::{
    request::ResponsesRequest, response::ResponsesResponse, tools::extract_request_tool_events,
};
use crate::protocol::openai::shared::{
    exchange::ParsedOpenAiExchange, http::OpenAiHttpExchange, images::extract_openai_request_images,
};

/// Parses a Responses exchange selected by protocol detection.
#[must_use]
pub fn parse_responses_exchange(exchange: &HttpExchange) -> Option<ParsedOpenAiExchange> {
    let payload = exchange.request.body().json();
    let request = ResponsesRequest::parse(payload, exchange.request.body().truncated());
    let decoded = OpenAiHttpExchange::decode(exchange);
    let response =
        ResponsesResponse::assemble(&decoded.documents.values, decoded.documents.incomplete);
    decoded.finish(
        request.conversation(),
        request.texts(),
        payload.map_or_else(Vec::new, extract_openai_request_images),
        payload.map_or_else(Vec::new, extract_request_tool_events),
        &response,
    )
}
