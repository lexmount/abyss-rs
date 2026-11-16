//! Response facts produced independently of request parsing and event retention.

use abyss_plugin_protocol::event::Conversation;
use serde_json::Value;

use super::usage::TokenUsage;

/// Decoded response documents and independent observations about missing data.
/// Transport adapters supply facts; each dialect decides content completeness.
pub struct ResponseInput<'a> {
    /// Successfully decoded documents in response order.
    pub values: &'a [Value],
    /// The underlying capture ended before the transport's normal boundary.
    pub capture_truncated: bool,
    /// At least one observed document could not be decoded.
    pub decode_failed: bool,
    /// The response accumulator discarded documents after reaching its budget.
    pub assembly_overflowed: bool,
}

impl<'a> ResponseInput<'a> {
    /// Wraps decoded documents with no observed data loss.
    #[must_use]
    pub const fn new(values: &'a [Value]) -> Self {
        Self {
            values,
            capture_truncated: false,
            decode_failed: false,
            assembly_overflowed: false,
        }
    }

    /// Conservative completeness for dialects without authoritative snapshots.
    #[must_use]
    pub const fn is_incomplete(&self) -> bool {
        self.capture_truncated || self.decode_failed || self.assembly_overflowed
    }
}

pub struct ResponseContent {
    pub has_content: bool,
    pub conversation: Conversation,
    pub usage: Option<TokenUsage>,
    pub model: Option<String>,
    pub response_id: Option<String>,
    pub event_types: Vec<String>,
}
