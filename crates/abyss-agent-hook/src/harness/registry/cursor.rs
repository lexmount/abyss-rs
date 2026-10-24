//! Cursor Local identity and user-turn declarations from native provider headers.
//! Cursor cloud RPC parsing is outside this detector's boundary.

use abyss_mitm::SourceProcess;
use http::HeaderMap;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
};

use super::{HarnessDetector, client_version, header};

pub(super) struct CursorDetector;

impl HarnessDetector for CursorDetector {
    fn detect(
        &self,
        source: Option<&SourceProcess>,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let user_agent = header(headers, "user-agent")?;
        if !user_agent.starts_with("Cursor-CLI/") {
            return None;
        }
        Some(HarnessDetection {
            harness_id: BuiltInHarness::Cursor.into(),
            evidence: vec![HarnessEvidence::Header("user-agent")],
            version: client_version(user_agent, &["cursor-cli/"]),
            working_directory: source.and_then(|source| source.working_directory.clone()),
        })
    }
}

pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    AgentDeclaration {
        // Cursor Local sends its generationUUID on every inference in one
        // user turn, including the follow-up after a local tool completes.
        turn_id: source
            .headers
            .and_then(|headers| header(headers, "x-request-id"))
            .map(str::to_owned),
        ..AgentDeclaration::default()
    }
}
