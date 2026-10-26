//! Anthropic Messages wire protocol parsing.

mod exchange;
mod model;
mod session;

pub use exchange::parse_anthropic_messages_exchange;
#[cfg(test)]
pub use model::AnthropicSessionIdSource;
pub use model::ParsedAnthropicMessagesExchange;

#[cfg(test)]
mod tests;
