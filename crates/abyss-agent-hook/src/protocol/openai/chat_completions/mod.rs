//! Chat Completions wire protocol parsing.

mod exchange;
mod request;
mod response;
mod tools;

pub use exchange::parse_chat_completions_exchange;

#[cfg(test)]
mod tests;
