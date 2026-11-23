//! DSH identity from the shared headless, TUI, and Web request marker.
//! Protocol selection and parsing remain independent of this detector.

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessId};

use super::{HarnessDetector, HarnessRequest, client_version, header};

const USER_AGENT_PREFIX: &str = "deepseek-harness/";

pub(super) struct DeepSeekHarnessDetector;

impl HarnessDetector for DeepSeekHarnessDetector {
    fn detect(&self, request: &HarnessRequest<'_>) -> Option<HarnessDetection> {
        let user_agent = header(request.headers, "user-agent")?;
        if !user_agent.starts_with(USER_AGENT_PREFIX) {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::DeepSeekHarness),
            version: client_version(user_agent, &[USER_AGENT_PREFIX]),
        })
    }
}
