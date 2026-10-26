//! Harness-independent LLM protocol identity and deterministic detection.
//!
//! `detection` selects a wire dialect. `openai/responses` owns Responses HTTP
//! and WebSocket parsing; `openai/chat_completions` owns message/choice parsing.
//! `anthropic/messages` and `anthropic/claude_web` own their exchange contracts.
//! Family `shared` modules reuse content rules, without combining dialect state.
//! `model` contains provider-neutral values; root `shared` contains bounded
//! decoding, text/image helpers, and transport metadata. Harness detection and
//! public event normalization remain outside this boundary.

pub mod anthropic;
pub mod detection;
pub mod model;
pub mod openai;
pub mod shared;

pub use detection::{
    AnthropicProtocol, ClaudeWebProtocol, LlmProtocol, OpenAiProtocol, ProtocolDetector,
};
