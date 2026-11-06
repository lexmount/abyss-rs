//! Protocol-level token counters.

use serde::Serialize;

/// Normalized token counters extracted from provider traffic.
///
/// The four billing counters are disjoint: `input_tokens`, `cache_read_tokens`,
/// `cache_write_tokens`, and `output_tokens` never count the same token twice,
/// whatever convention the provider used on the wire. `reasoning_tokens` is a
/// breakdown of `output_tokens`, and `total_tokens` is always the sum of the
/// four billing counters.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
#[expect(
    clippy::struct_field_names,
    reason = "provider payloads use token counter names with explicit token suffixes"
)]
pub struct TokenUsage {
    /// Prompt/input tokens neither read from nor written into a provider cache.
    pub input_tokens: i64,
    /// Tokens produced by model output, including reasoning.
    pub output_tokens: i64,
    /// Input tokens served from a provider cache.
    pub cache_read_tokens: i64,
    /// Input tokens written into a provider cache.
    pub cache_write_tokens: i64,
    /// Part of `output_tokens` spent in reasoning traces when providers expose it.
    pub reasoning_tokens: i64,
    /// Sum of the four disjoint billing counters.
    pub total_tokens: i64,
}

impl TokenUsage {
    /// Builds usage from disjoint counters and derives the total from them.
    #[must_use]
    pub const fn from_parts(
        input_tokens: i64,
        cache_read_tokens: i64,
        cache_write_tokens: i64,
        output_tokens: i64,
        reasoning_tokens: i64,
    ) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens,
            cache_write_tokens,
            reasoning_tokens,
            total_tokens: input_tokens
                .saturating_add(cache_read_tokens)
                .saturating_add(cache_write_tokens)
                .saturating_add(output_tokens),
        }
    }

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

    /// Usage assigned to the request-side event: every input-side counter.
    #[must_use]
    pub const fn request_side(&self) -> Self {
        Self::from_parts(
            self.input_tokens,
            self.cache_read_tokens,
            self.cache_write_tokens,
            0,
            0,
        )
    }

    /// Usage assigned to the response-side event: output and its reasoning part.
    #[must_use]
    pub const fn response_side(&self) -> Self {
        Self::from_parts(0, 0, 0, self.output_tokens, self.reasoning_tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::TokenUsage;

    #[test]
    fn splits_disjoint_counters_between_request_and_response() {
        let usage = TokenUsage::from_parts(2, 77_000, 400, 150, 40);

        let request = usage.request_side();
        let response = usage.response_side();

        assert_eq!(usage.total_tokens, 77_552);
        assert_eq!(request.total_tokens, 77_402);
        assert_eq!(request.cache_read_tokens, 77_000);
        assert_eq!(request.cache_write_tokens, 400);
        assert_eq!(response.total_tokens, 150);
        assert_eq!(response.reasoning_tokens, 40);
        assert_eq!(
            request.total_tokens.saturating_add(response.total_tokens),
            usage.total_tokens
        );
    }
}
