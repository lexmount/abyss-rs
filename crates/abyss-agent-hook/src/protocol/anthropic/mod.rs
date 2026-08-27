//! Anthropic-family public and private protocol parsing.

pub mod claude_web;
pub mod messages;

pub use claude_web::{ClaudeWebContext, ParsedClaudeWebExchange, parse_claude_web_exchange};
pub use messages::*;
