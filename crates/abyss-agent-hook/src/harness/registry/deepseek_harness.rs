//! DSH identity from the shared headless, TUI, and Web request marker.
//! Protocol selection and parsing remain independent of this detector.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId};

use super::{HarnessDetector, client_version, header};

const USER_AGENT_PREFIX: &str = "deepseek-harness/";

pub(super) struct DeepSeekHarnessDetector;

impl HarnessDetector for DeepSeekHarnessDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let user_agent = header(headers, "user-agent")?;
        if !user_agent.starts_with(USER_AGENT_PREFIX) {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::DeepSeekHarness),
            evidence: vec![HarnessEvidence::Header("user-agent")],
            version: client_version(user_agent, &[USER_AGENT_PREFIX]),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}
