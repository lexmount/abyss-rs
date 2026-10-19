//! OpenAI-family protocol dispatch; each dialect owns its wire parser.

pub mod chat_completions;
pub mod responses;
pub mod shared;

pub use responses::{parse_openai_websocket_message, websocket::OpenAiWebSocketAccumulator};
pub use shared::exchange::ParsedOpenAiExchange;

/// Dispatches a previously detected OpenAI wire dialect.
#[must_use]
pub fn parse_openai_exchange(
    exchange: &abyss_mitm::HttpExchange,
    protocol: super::OpenAiProtocol,
) -> Option<ParsedOpenAiExchange> {
    match protocol {
        super::OpenAiProtocol::ChatCompletions => {
            chat_completions::parse_chat_completions_exchange(exchange)
        }
        super::OpenAiProtocol::Responses => responses::parse_responses_exchange(exchange),
    }
}

#[cfg(test)]
mod tests;
