//! `DeepSeek` Harness recognition from its shared User-Agent, without client-mode inference.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId};

use super::{HarnessDetector, client_version, header};

pub(super) struct DeepSeekHarnessDetector;

impl HarnessDetector for DeepSeekHarnessDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let version = client_version(header(headers, "user-agent")?, &["deepseek-harness/"])?;
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::DeepSeekHarness),
            evidence: vec![HarnessEvidence::Header("user-agent")],
            version: Some(version),
            working_directory: flow.source_working_directory().map(str::to_owned),
            session_id: None,
        })
    }
}
