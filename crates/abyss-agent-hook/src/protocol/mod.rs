//! Harness-independent LLM protocol identity and deterministic detection.

pub mod anthropic;
pub mod detection;
pub mod model;
pub mod openai;
pub mod sse;

pub use detection::{
    AnthropicProtocol, ClaudeWebProtocol, LlmProtocol, OpenAiProtocol, ProtocolDetector,
};
