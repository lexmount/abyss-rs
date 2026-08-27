//! Content-retention policy applied after Harness and protocol detection.

use serde::{Deserialize, Serialize};

/// Independent content retention controls for Harness usage events.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "the policy contract intentionally exposes four independent switches"
)]
#[serde(default, deny_unknown_fields)]
pub struct HarnessUsageContentConfig {
    /// Whether provider token counters are retained.
    pub token_usage: bool,
    /// Whether conversation request/response text is retained.
    pub conversation_text: bool,
    /// Whether tool call and tool result content is retained.
    pub tool_calls: bool,
    /// Whether image metadata and attachments are retained.
    pub images: bool,
}

impl Default for HarnessUsageContentConfig {
    fn default() -> Self {
        Self {
            token_usage: true,
            conversation_text: true,
            tool_calls: true,
            images: true,
        }
    }
}
