//! OpenAI-family protocol parsing shared by all detected Harnesses.

mod chat_tools;
pub mod conversation;
pub mod responses;
pub mod websocket;

pub use responses::*;
pub use websocket::OpenAiWebSocketAccumulator;
