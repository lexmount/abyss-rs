//! Claude Desktop detection from application identity and private request markers.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId};

use super::{HarnessDetector, client_version, header};

pub(super) struct ClaudeDesktopDetector;

impl HarnessDetector for ClaudeDesktopDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
    ) -> Option<HarnessDetection> {
        let mut evidence = Vec::new();
        if let Some(source) = &flow.source_process {
            if let Some(application_id) = source
                .application_id
                .as_deref()
                .filter(|value| *value == "com.anthropic.claudefordesktop.helper")
            {
                evidence.push(HarnessEvidence::ApplicationId(application_id.to_owned()));
            } else if source
                .name
                .as_deref()
                .into_iter()
                .chain(source.executable_path.as_deref())
                .any(is_desktop_process)
            {
                evidence.push(HarnessEvidence::Process(
                    source
                        .name
                        .clone()
                        .or_else(|| source.executable_path.clone())
                        .unwrap_or_default(),
                ));
            }
        }
        if header(headers, "anthropic-client-platform") == Some("desktop_app")
            || header(headers, "anthropic-client-app") == Some("com.anthropic.claudefordesktop")
        {
            evidence.push(HarnessEvidence::Header("anthropic-client-app"));
        }
        if evidence.is_empty() {
            return None;
        }
        if path.contains("/organizations/") && path.ends_with("/completion") {
            evidence.push(HarnessEvidence::Path(path.to_owned()));
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::ClaudeDesktop),
            evidence,
            version: header(headers, "user-agent")
                .and_then(|user_agent| client_version(user_agent, &["claude/"])),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

fn is_desktop_process(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == "claude helper" || value.contains("/claude.app/")
}
