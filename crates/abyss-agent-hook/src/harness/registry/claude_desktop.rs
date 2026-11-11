//! Claude Desktop detection from application identity and private request markers.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessId};

use super::{HarnessDetector, claude_code::ClaudeCodeDetector, client_version, header};

pub(super) struct ClaudeDesktopDetector;

impl HarnessDetector for ClaudeDesktopDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        // The bundled Code executable is a separate Harness, even when its
        // path or inherited request headers also look like Desktop.
        if ClaudeCodeDetector::has_explicit_source(flow) {
            return None;
        }
        let source = flow.source_process.as_ref().is_some_and(|source| {
            matches!(
                source.application_id.as_deref(),
                Some("com.anthropic.claudefordesktop" | "com.anthropic.claudefordesktop.helper")
            ) || source
                .name
                .as_deref()
                .into_iter()
                .chain(source.executable_path.as_deref())
                .any(is_desktop_process)
        });
        let marked = header(headers, "anthropic-client-platform") == Some("desktop_app")
            || header(headers, "anthropic-client-app") == Some("com.anthropic.claudefordesktop");
        if !source && !marked {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::ClaudeDesktop),
            version: header(headers, "user-agent")
                .and_then(|user_agent| client_version(user_agent, &["claude/"])),
        })
    }
}

fn is_desktop_process(value: &str) -> bool {
    let value = value.trim().to_ascii_lowercase();
    value == "claude helper" || value.contains("/claude.app/")
}
