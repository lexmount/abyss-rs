//! Codex detection from product-owned process and request markers.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId};

use super::{HarnessDetector, client_version, header};

pub(super) struct CodexDetector;

impl HarnessDetector for CodexDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
    ) -> Option<HarnessDetection> {
        let mut evidence = Vec::new();
        if let Some(process) = flow.source_process.as_ref()
            && process
                .name
                .as_deref()
                .is_some_and(|name| normalize(name) == "codex")
        {
            evidence.push(HarnessEvidence::Process(
                process.name.clone().unwrap_or_default(),
            ));
        }
        if headers
            .keys()
            .any(|name| name.as_str().to_ascii_lowercase().starts_with("x-codex-"))
        {
            evidence.push(HarnessEvidence::Header("x-codex-*"));
        }
        let user_agent = header(headers, "user-agent").unwrap_or_default();
        let originator = header(headers, "originator").unwrap_or_default();
        if format!("{path} {user_agent} {originator}")
            .to_ascii_lowercase()
            .contains("codex")
        {
            evidence.push(HarnessEvidence::Path(path.to_owned()));
        }
        if evidence.is_empty() {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::Codex),
            evidence,
            version: client_version(user_agent, &["codex/tui/", "codex/desktop/", "codex/"]),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

fn normalize(value: &str) -> String {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}
