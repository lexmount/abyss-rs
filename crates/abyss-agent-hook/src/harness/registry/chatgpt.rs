//! Attribute the desktop chat operation independently of the shared Codex helper.

use abyss_mitm::FlowContext;
use http::Request;

use super::{BuiltInHarness, HarnessDetection, HarnessId, HarnessMatcher, HarnessUsageConfig};
use crate::protocol::openai::chatgpt::matches_request;

pub(super) fn detect<B>(
    flow: &FlowContext,
    request: &Request<B>,
    config: &HarnessUsageConfig,
) -> Option<HarnessDetection> {
    if !matches_request(flow, request) {
        return None;
    }
    let harness_id = HarnessId::from(BuiltInHarness::ChatGpt);
    let native = flow
        .source_process
        .as_ref()
        .and_then(|p| p.application_id.as_deref());
    let configured = config.harnesses.get(&harness_id).is_some_and(|h| {
        h.matchers
            .iter()
            .any(|m| HarnessMatcher::new(m).matches(flow))
    });
    (configured
        || matches!(
            native,
            Some(
                "com.openai.chat"
                    | "com.openai.chat.helper"
                    | "com.openai.codex"
                    | "com.openai.codex.helper"
            )
        ))
    .then_some(HarnessDetection {
        harness_id,
        version: None,
    })
}
