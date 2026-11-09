//! Owned request projections shared by inspection and exchange assembly.
//! Captured bodies retain them only for their own observation lifetime.

use std::sync::Arc;

use abyss_plugin_protocol::event::Conversation;
use serde_json::Value;

use super::{image::ParsedImageAttachment, usage::TokenUsage};
use crate::protocol::LlmProtocol;

/// An optional protocol projection prepared before forwarding.
#[derive(Clone)]
pub struct ParsedAgentRequest {
    pub(crate) projection: Option<(LlmProtocol, Arc<RequestContent>)>,
}

/// Request facts independent of provider responses and audit retention.
#[derive(Clone)]
pub struct RequestContent {
    pub carries_messages: bool,
    pub conversation: Conversation,
    pub images: Vec<ParsedImageAttachment>,
    pub metadata: RequestMetadata,
    pub usage: Option<TokenUsage>,
    pub file_uuids: Vec<String>,
    pub assistant_message_uuid: Option<String>,
}

#[derive(Clone)]
pub struct RequestMetadata {
    pub model: Option<String>,
    pub tool_definitions: Option<Value>,
    pub previous_response_id: Option<String>,
    pub client_metadata: Option<Value>,
}

impl RequestContent {
    pub const fn is_empty(&self) -> bool {
        !self.carries_messages && self.images.is_empty() && self.file_uuids.is_empty()
    }
}
