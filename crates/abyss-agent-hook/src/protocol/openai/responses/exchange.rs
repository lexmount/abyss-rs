//! Responses HTTP exchanges compose the same request, response and assembly stages.

use super::parser::ResponsesParser;
use crate::protocol::{
    openai::shared::{exchange::ParsedOpenAiExchange, http::OpenAiHttpExchange},
    parser::parse_http_exchange,
};
use abyss_mitm::HttpExchange;

#[must_use]
pub fn parse_responses_exchange(exchange: &HttpExchange) -> Option<ParsedOpenAiExchange> {
    parse_http_exchange::<ResponsesParser, _, _>(exchange, OpenAiHttpExchange::assemble_exchange)
}
