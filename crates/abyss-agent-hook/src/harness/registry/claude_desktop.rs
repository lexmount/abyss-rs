//! Claude Desktop detection from application identity and private request markers.

use crate::harness::{BuiltInHarness, HarnessDetection, HarnessId};

use super::{HarnessDetector, HarnessRequest, client_version, header};

// The main app and its helpers. Install paths and the host platform
// header also cover the Claude Code that Desktop bundles and launches.
const APPLICATION_IDS: &[&str] = &[
    "com.anthropic.claudefordesktop",
    "com.anthropic.claudefordesktop.helper",
];

pub(super) struct ClaudeDesktopDetector;

impl HarnessDetector for ClaudeDesktopDetector {
    fn detect(&self, request: &HarnessRequest<'_>) -> Option<HarnessDetection> {
        let application = request
            .flow
            .source_process
            .as_ref()
            .and_then(|source| source.application_id.as_deref())
            .is_some_and(|id| APPLICATION_IDS.contains(&id));
        let marked = header(request.headers, "anthropic-client-app")
            == Some("com.anthropic.claudefordesktop");
        if !application && !marked {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::ClaudeDesktop),
            version: header(request.headers, "user-agent")
                .and_then(|user_agent| client_version(user_agent, &["claude/"])),
        })
    }
}
