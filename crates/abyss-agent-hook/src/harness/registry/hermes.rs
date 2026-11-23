//! Hermes identity and user-turn declarations; protocol parsers resolve sessions.

use abyss_mitm::{ModuleRuntime, ProcessEntry};

use crate::harness::{AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection};

use super::{HarnessDetector, HarnessRequest, client_version, header};

const SESSION_ID: &str = "x-hermes-session-id";
const TURN_ID: &str = "x-hermes-turn-id";

// Hermes signs its managed interpreter with this identity on macOS. Generic
// Python names and installation paths do not identify the calling Harness.
const APPLICATION_ID: &str = "com.nousresearch.hermes.managed-python";

pub(super) struct HermesDetector;

impl HarnessDetector for HermesDetector {
    fn detect(&self, request: &HarnessRequest<'_>) -> Option<HarnessDetection> {
        let user_agent = header(request.headers, "user-agent").unwrap_or_default();
        let normalized = user_agent.to_ascii_lowercase();
        let marked = header(request.headers, SESSION_ID).is_some()
            || normalized.starts_with("hermesagent/")
            || normalized.contains("(hermes agent)")
            || header(request.headers, "originator")
                .is_some_and(|value| value.eq_ignore_ascii_case("hermes-agent"));
        let source = request.flow.source_process.as_ref();
        let application =
            source.and_then(|source| source.application_id.as_deref()) == Some(APPLICATION_ID);
        let module = matches!(
            source.and_then(|source| source.entry_point.as_ref()),
            Some(ProcessEntry::Module {
                runtime: ModuleRuntime::Python,
                name,
            }) if name == "hermes_cli.main"
        );
        if !application && !module && !marked {
            return None;
        }
        Some(HarnessDetection {
            harness_id: BuiltInHarness::Hermes.into(),
            // Do not report a compatibility codex_cli_rs version as Hermes'.
            version: client_version(user_agent, &["hermesagent/"]),
        })
    }
}

pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    AgentDeclaration {
        // Only per-request headers describe a user turn; upgrade headers can
        // outlive many turns on a persistent WebSocket.
        turn_id: source
            .headers
            .and_then(|headers| header(headers, TURN_ID))
            .map(str::to_owned),
        ..AgentDeclaration::default()
    }
}
