//! Claude Code detection from process identity and product request markers,
//! and what Claude Code declares in its `x-claude-code-*` headers: the
//! request class, and the subagent and user prompt a request works for.

use abyss_plugin_protocol::event::EventPurpose;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessId,
};

use super::{HarnessDetector, HarnessRequest, client_version, header};

/// Kind of request: `main`, `subagent`, `compaction`, `auxiliary`, and others.
const REQUEST_CLASS: &str = "x-claude-code-request-class";
/// Subagent the request belongs to.
const AGENT_ID: &str = "x-claude-code-agent-id";
/// Subagent that spawned the request's subagent.
const PARENT_AGENT_ID: &str = "x-claude-code-parent-agent-id";
/// User prompt the request ultimately works for.
const PROMPT_ID: &str = "x-claude-code-prompt-id";
/// Signing identifier of every Claude Code build, standalone or bundled.
/// Process names are not identity: self-updated builds run as their version.
const APPLICATION_ID: &str = "com.anthropic.claude-code";
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
    fn detect(&self, request: &HarnessRequest<'_>) -> Option<HarnessDetection> {
        let application = request
            .flow
            .source_process
            .as_ref()
            .and_then(|source| source.application_id.as_deref())
            == Some(APPLICATION_ID);
        let user_agent = header(request.headers, "user-agent").unwrap_or_default();
        // Desktop also sends `claude-cli/cowork-feedback`, so the product
        // token must carry a version.
        let product = user_agent
            .split_whitespace()
            .next()
            .and_then(|product| product.strip_prefix("claude-cli/"))
            .is_some_and(|version| version.starts_with(|c: char| c.is_ascii_digit()));
        let marked = request
            .headers
            .keys()
            .any(|name| name.as_str().starts_with("x-claude-code-"));
        if !application && !product && !marked {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::ClaudeCode),
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
        })
    }
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
