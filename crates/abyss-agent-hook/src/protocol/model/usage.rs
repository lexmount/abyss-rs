//! Protocol-level token counters and their extraction provenance.

use serde::Serialize;

/// Normalized token counters extracted from provider traffic.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "provider payloads use token counter names with explicit token suffixes"
)]
pub struct TokenUsage {
    /// Tokens consumed by prompt/input content.
    pub input_tokens: i64,
    /// Tokens produced by model output.
    pub output_tokens: i64,
    /// Input tokens served from a provider cache.
    pub cache_read_tokens: i64,
    /// Input tokens written into a provider cache.
    pub cache_write_tokens: i64,
    /// Tokens spent in model reasoning traces when providers expose them.
    pub reasoning_tokens: i64,
    /// Provider total, or a derived total when the provider omits one.
    pub total_tokens: i64,
}

impl TokenUsage {
    /// Returns true when every token counter is zero.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.input_tokens == 0
            && self.output_tokens == 0
            && self.cache_read_tokens == 0
            && self.cache_write_tokens == 0
            && self.reasoning_tokens == 0
            && self.total_tokens == 0
    }

    /// Usage assigned to the request-side event.
    #[must_use]
    pub const fn request_side(&self) -> Self {
        Self {
            input_tokens: self.input_tokens,
            output_tokens: 0,
            cache_read_tokens: self.cache_read_tokens,
            cache_write_tokens: self.cache_write_tokens,
            reasoning_tokens: 0,
            total_tokens: self.input_tokens,
        }
    }

    /// Usage assigned to the response-side event.
    #[must_use]
    pub const fn response_side(&self) -> Self {
        Self {
            input_tokens: 0,
            output_tokens: self.output_tokens,
            cache_read_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: self.reasoning_tokens,
            total_tokens: self.output_tokens,
        }
    }
}

/// Provenance of token counters attached to one parsed exchange.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenUsageSource {
    /// Counters were present in provider request or response payloads.
    ProviderReported,
    /// Counters were estimated from visible request and response content.
    EstimatedVisibleContent,
    /// Neither provider counters nor an estimate were available.
    Absent,
}

impl TokenUsageSource {
    /// Classifies an empty usage record as absent and a non-empty one as provider reported.
    #[must_use]
    pub const fn provider_or_absent(usage: &TokenUsage) -> Self {
        if usage.is_empty() {
            Self::Absent
        } else {
            Self::ProviderReported
        }
    }

    /// Returns whether the counters were estimated from visible content.
    #[must_use]
    pub const fn is_estimated(self) -> bool {
        matches!(self, Self::EstimatedVisibleContent)
    }
}
