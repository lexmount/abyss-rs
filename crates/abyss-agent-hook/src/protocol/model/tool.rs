//! Provider-neutral structured tool activity extracted from agent traffic.
//!
//! Provider parsers retain their wire-specific decoding, while this module
//! defines the common call/result shape consumed by event construction and the
//! dashboard metadata contract.

use serde::Serialize;

/// Structured tool activity extracted from one provider exchange.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ParsedToolEvent {
    /// A completed model-requested tool invocation.
    ToolCall {
        /// Provider output/content item id when it differs from the call id.
        item_id: Option<String>,
        /// Stable identifier shared with the later tool result.
        call_id: Option<String>,
        /// Provider tool name, such as `Bash`, `Read`, or `exec`.
        name: Option<String>,
        /// Complete provider-visible tool input.
        input: String,
    },
    /// A tool result submitted back to the model.
    ToolResult {
        /// Stable identifier shared with the originating tool call.
        call_id: Option<String>,
        /// Provider-visible result text or a bounded attachment descriptor.
        output: String,
    },
}
