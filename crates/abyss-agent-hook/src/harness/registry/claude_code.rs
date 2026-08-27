//! Claude Code detection from process identity and product request markers.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessEvidence, HarnessId};

use super::{HarnessDetector, client_version, header};

pub(super) struct ClaudeCodeDetector;

impl HarnessDetector for ClaudeCodeDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
    ) -> Option<HarnessDetection> {
        if path.contains("/organizations/") && path.ends_with("/completion") {
            return None;
        }
        let mut evidence = Vec::new();
        if let Some(source) = &flow.source_process
            && source
                .name
                .as_deref()
                .into_iter()
                .chain(source.executable_path.as_deref())
                .any(is_claude_code_process)
        {
            evidence.push(HarnessEvidence::Process(
                source
                    .name
                    .clone()
                    .or_else(|| source.executable_path.clone())
                    .unwrap_or_default(),
            ));
        }
        let user_agent = header(headers, "user-agent").unwrap_or_default();
        let originator = header(headers, "originator").unwrap_or_default();
        let combined = format!("{path} {user_agent} {originator}").to_ascii_lowercase();
        if [
            "claude-code",
            "claude_code",
            "claude-cli",
            "claude/",
            "/api/claude_",
        ]
        .iter()
        .any(|marker| combined.contains(marker))
        {
            evidence.push(HarnessEvidence::Header("claude-code"));
        }
        if evidence.is_empty() {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::ClaudeCode),
            evidence,
            version: client_version(
                user_agent,
                &[
                    "claude-code/",
                    "claude_code/",
                    "claude-cli/",
                    "claude_cli/",
                    "claude/",
                ],
            ),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

fn is_claude_code_process(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == "claude"
        || value == "claude.exe"
        || value.contains("claude-code")
        || value.contains("claude_code")
        || value.ends_with("\\claude.exe")
        || value.ends_with("/claude")
}
