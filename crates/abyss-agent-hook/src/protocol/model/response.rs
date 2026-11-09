//! Response facts produced independently of request parsing and event retention.

use abyss_plugin_protocol::event::Conversation;

use super::usage::TokenUsage;

pub struct ResponseContent {
    pub has_content: bool,
    pub conversation: Conversation,
    pub usage: Option<TokenUsage>,
    pub model: Option<String>,
    pub response_id: Option<String>,
    pub event_types: Vec<String>,
}
