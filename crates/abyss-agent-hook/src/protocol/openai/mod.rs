//! OpenAI-family protocol parsing shared by all detected Harnesses.

pub mod responses;
pub mod websocket;

pub use responses::*;
pub use websocket::OpenAiWebSocketAccumulator;
