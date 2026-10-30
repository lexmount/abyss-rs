//! Claude Code detection from process identity and product request markers,
//! and what Claude Code declares in its `x-claude-code-*` headers: the
//! request class, and the subagent and user prompt a request works for.

use abyss_mitm::FlowContext;
use abyss_plugin_protocol::event::EventPurpose;
use http::HeaderMap;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
    HarnessId,
};

use super::{HarnessDetector, client_version, header};

/// Kind of request: `main`, `subagent`, `compaction`, `auxiliary`, and others.
const REQUEST_CLASS: &str = "x-claude-code-request-class";
/// Subagent the request belongs to.
const AGENT_ID: &str = "x-claude-code-agent-id";
/// Subagent that spawned the request's subagent.
const PARENT_AGENT_ID: &str = "x-claude-code-parent-agent-id";
/// User prompt the request ultimately works for.
const PROMPT_ID: &str = "x-claude-code-prompt-id";
/// Reads the request class, subagent, and prompt Claude Code declares in its
/// headers.
pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    let declared = |name: &str| {
        source
            .request_or_connection_headers()
            .and_then(|headers| header(headers, name))
            .map(str::to_owned)
    };
    let class = source
        .headers
        .and_then(|headers| header(headers, REQUEST_CLASS));
    AgentDeclaration {
        purpose: (class == Some("compaction")).then_some(EventPurpose::Compaction),
        subagent_id: declared(AGENT_ID),
        parent_subagent_id: declared(PARENT_AGENT_ID),
        turn_id: declared(PROMPT_ID),
    }
}

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

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::event::EventPurpose;
    use http::HeaderMap;

    use crate::harness::{AgentDeclaration, DeclarationSource};

    use super::declare;

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, value.parse().unwrap());
        }
        headers
    }

    fn declared(pairs: &[(&'static str, &str)]) -> AgentDeclaration {
        declare(&DeclarationSource {
            headers: Some(&headers(pairs)),
            connection_headers: None,
            client_metadata: None,
        })
    }

    #[test]
    fn request_class_names_compaction() {
        let compaction = declared(&[
            ("x-claude-code-session-id", "session-1"),
            ("x-claude-code-request-class", "compaction"),
            ("x-claude-code-compaction", "manual"),
        ]);
        assert_eq!(compaction.purpose, Some(EventPurpose::Compaction));
    }

    #[test]
    fn other_and_undeclared_requests_declare_nothing() {
        for class in ["main", "subagent", "auxiliary"] {
            let declaration = declared(&[
                ("x-claude-code-session-id", "session-1"),
                ("x-claude-code-request-class", class),
            ]);
            assert_eq!(declaration, AgentDeclaration::default(), "{class}");
        }
        assert_eq!(declared(&[]), AgentDeclaration::default());
    }

    #[test]
    fn agent_headers_declare_the_subagent_and_the_prompt() {
        let main = declared(&[
            ("x-claude-code-session-id", "session-1"),
            ("x-claude-code-prompt-id", "prompt-1"),
        ]);
        assert_eq!(
            (main.subagent_id, main.parent_subagent_id, main.turn_id),
            (None, None, Some("prompt-1".to_owned()))
        );
        let nested = declared(&[
            ("x-claude-code-session-id", "session-1"),
            ("x-claude-code-agent-id", "a-2"),
            ("x-claude-code-parent-agent-id", "a-1"),
            ("x-claude-code-prompt-id", "prompt-1"),
        ]);
        assert_eq!(
            (
                nested.subagent_id.as_deref(),
                nested.parent_subagent_id.as_deref(),
                nested.turn_id.as_deref()
            ),
            (Some("a-2"), Some("a-1"), Some("prompt-1"))
        );
        // Codex's thread headers mean nothing to Claude Code.
        let codex = declared(&[
            ("session-id", "session-1"),
            ("thread-id", "t-2"),
            ("x-codex-parent-thread-id", "session-1"),
        ]);
        assert_eq!(codex, AgentDeclaration::default());
    }
}
