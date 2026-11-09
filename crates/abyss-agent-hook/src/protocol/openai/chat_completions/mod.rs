//! Chat Completions wire protocol parsing.

mod exchange;
mod parser;
pub use parser::ChatCompletionsParser;
mod request;
mod response;
mod tools;

pub use exchange::parse_chat_completions_exchange;

#[cfg(test)]
mod tests;
