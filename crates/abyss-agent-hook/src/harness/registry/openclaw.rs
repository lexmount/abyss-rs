//! `OpenClaw` identity and session declarations, independent of provider protocol.
//! Its transport turn id identifies a model call, not the whole user turn.

use abyss_mitm::FlowContext;
use http::HeaderMap;
use serde_json::Value;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
};

use super::{HarnessDetector, client_version, header, process_evidence};

const SESSION_ID: &str = "x-openclaw-session-id";

pub(super) struct OpenClawDetector;

impl HarnessDetector for OpenClawDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let user_agent = header(headers, "user-agent").unwrap_or_default();
        let mut evidence = process_evidence(
            flow,
            &[
                "openclaw",
                "openclaw-gateway",
                "openclaw.mjs",
                "openclaw.js",
            ],
        )
        .into_iter()
        .collect::<Vec<_>>();
        let marker = if header(headers, SESSION_ID).is_some() {
            Some(SESSION_ID)
        } else if user_agent.to_ascii_lowercase().starts_with("openclaw/") {
            Some("user-agent")
        } else if header(headers, "originator")
            .is_some_and(|value| value.eq_ignore_ascii_case("openclaw"))
        {
            Some("originator")
        } else {
            None
        };
        if let Some(marker) = marker {
            evidence.push(HarnessEvidence::Header(marker));
        }
        if evidence.is_empty() {
            return None;
        }
        Some(HarnessDetection {
            harness_id: BuiltInHarness::OpenClaw.into(),
            evidence,
            version: client_version(user_agent, &["openclaw/"]),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    let session_id = source
        .headers
        .and_then(session_header)
        .or_else(|| {
            source
                .metadata
                .and_then(|metadata| metadata.get("openclaw_session_id"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .or_else(|| source.upgrade_headers.and_then(session_header));
    AgentDeclaration {
        session_id: session_id.map(str::to_owned),
        // x-openclaw-turn-id changes after a tool call. Preserve response_id
        // for downstream fallback instead of claiming a user turn here.
        ..AgentDeclaration::default()
    }
}

fn session_header(headers: &HeaderMap) -> Option<&str> {
    header(headers, SESSION_ID)
        .or_else(|| header(headers, "session_id"))
        .or_else(|| header(headers, "session-id"))
}
