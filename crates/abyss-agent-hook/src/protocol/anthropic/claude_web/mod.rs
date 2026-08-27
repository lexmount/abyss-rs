//! Claude Web private protocol parsing and auxiliary request context.

pub mod context;
pub mod conversation;

pub use context::ClaudeWebContext;
pub use conversation::{ParsedClaudeWebExchange, parse_claude_web_exchange};
