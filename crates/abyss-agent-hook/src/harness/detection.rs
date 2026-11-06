//! Harness identity produced independently of LLM parsing.

use super::HarnessId;

/// Harness identity composed with a separately parsed LLM interaction.
#[derive(Clone, Debug)]
pub struct HarnessDetection {
    pub harness_id: HarnessId,
    pub version: Option<String>,
}
