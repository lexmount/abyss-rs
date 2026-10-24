//! Hermes identity and user-turn declarations; protocol parsers resolve sessions.

use std::sync::LazyLock;

use abyss_mitm::SourceProcess;
use http::HeaderMap;

use crate::config::HarnessMatcherConfig;
use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
    matcher::HarnessMatcher,
};

use super::{HarnessDetector, client_version, header};

const SESSION_ID: &str = "x-hermes-session-id";
const TURN_ID: &str = "x-hermes-turn-id";

// Hermes signs its managed interpreter with this identity on macOS. Generic
// Python names and installation paths do not identify the calling Harness.
static SOURCE_MATCHER: LazyLock<HarnessMatcherConfig> = LazyLock::new(|| HarnessMatcherConfig {
    application_ids: vec!["com.nousresearch.hermes.managed-python".to_owned()],
    ..HarnessMatcherConfig::default()
});

pub(super) struct HermesDetector;

impl HarnessDetector for HermesDetector {
    fn detect(
        &self,
        source: Option<&SourceProcess>,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let user_agent = header(headers, "user-agent").unwrap_or_default();
        let normalized = user_agent.to_ascii_lowercase();
        let marker = if header(headers, SESSION_ID).is_some() {
            Some(SESSION_ID)
        } else if normalized.starts_with("hermesagent/") || normalized.contains("(hermes agent)") {
            Some("user-agent")
        } else if header(headers, "originator")
            .is_some_and(|value| value.eq_ignore_ascii_case("hermes-agent"))
        {
            Some("originator")
        } else {
            None
        };
        let mut evidence = HarnessMatcher::new(&SOURCE_MATCHER)
            .matches(source)
            .unwrap_or_default();
        if let Some(marker) = marker {
            evidence.push(HarnessEvidence::Header(marker));
        }
        if evidence.is_empty() {
            return None;
        }
        Some(HarnessDetection {
            harness_id: BuiltInHarness::Hermes.into(),
            evidence,
            // Do not report a compatibility codex_cli_rs version as Hermes'.
            version: client_version(user_agent, &["hermesagent/"]),
            working_directory: source.and_then(|source| source.working_directory.clone()),
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
