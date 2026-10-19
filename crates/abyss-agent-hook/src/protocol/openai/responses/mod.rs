//! Responses wire protocol parsing.

mod exchange;
mod request;
mod response;
mod tools;
pub mod websocket;
mod websocket_frame;

pub use websocket_frame::parse_openai_websocket_message;

pub use exchange::parse_responses_exchange;

#[cfg(test)]
mod tests;
