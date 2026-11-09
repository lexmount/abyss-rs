//! Chat Completions HTTP exchanges compose the same request, response and assembly stages.

use super::parser::ChatCompletionsParser;
use crate::protocol::{
    openai::shared::{exchange::ParsedOpenAiExchange, http::OpenAiHttpExchange},
    parser::parse_http_exchange,
};
use abyss_mitm::HttpExchange;

#[must_use]
pub fn parse_chat_completions_exchange(exchange: &HttpExchange) -> Option<ParsedOpenAiExchange> {
    parse_http_exchange::<ChatCompletionsParser, _, _>(
        exchange,
        OpenAiHttpExchange::assemble_exchange,
    )
}
