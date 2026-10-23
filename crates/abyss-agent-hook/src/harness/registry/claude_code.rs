//! Claude Code detection from process identity and product request markers,
//! and what Claude Code declares in its `x-claude-code-*` headers: the
//! request class, and the subagent and user prompt a request works for.

use abyss_mitm::FlowContext;
use abyss_plugin_protocol::event::EventPurpose;
use http::HeaderMap;
use serde_json::Value;

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
/// Line prefix Claude Code writes at the start of its first system block.
const BILLING_HEADER: &str = "x-anthropic-billing-header:";
/// System instruction Claude Code sends when naming the session it runs in.
const NAMING_INSTRUCTION: &str = "You are naming a coding session";

/// Reads the request class, subagent, and prompt Claude Code declares in its
/// headers, and recognizes the call that names its session.
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
    let purpose = if class == Some("compaction") {
        Some(EventPurpose::Compaction)
    } else if source.body.is_some_and(names_session) {
        Some(EventPurpose::SessionTitle)
    } else {
        None
    };
    AgentDeclaration {
        purpose,
        subagent_id: declared(AGENT_ID),
        parent_subagent_id: declared(PARENT_AGENT_ID),
        root_turn_id: declared(PROMPT_ID),
    }
}

/// Claude Code names its session from a dedicated call: the billing header
/// opens the first system block and a system block carries the naming
/// instruction.
fn names_session(body: &Value) -> bool {
    let (first, blocks) = match body.get("system") {
        Some(Value::String(text)) => (Some(text.as_str()), vec![text.as_str()]),
        Some(Value::Array(blocks)) => {
            let texts = blocks
                .iter()
                .filter_map(|block| block.get("text").and_then(Value::as_str))
                .collect::<Vec<_>>();
            (
                blocks
                    .first()
                    .and_then(|block| block.get("text"))
                    .and_then(Value::as_str),
                texts,
            )
        }
        _ => return false,
    };
    first.is_some_and(|text| text.starts_with(BILLING_HEADER))
        && blocks.iter().any(|text| text.contains(NAMING_INSTRUCTION))
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
    use serde_json::{Value, json};

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
            body: None,
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
            (main.subagent_id, main.parent_subagent_id, main.root_turn_id),
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
                nested.root_turn_id.as_deref()
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

    fn naming_body(system: &Value) -> Value {
        json!({
            "model": "claude-haiku-5-5",
            "system": system,
            "messages": [{"role": "user", "content": "<session>\n修复登录\n</session>"}]
        })
    }

    fn naming_system() -> Value {
        json!([
            {"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.296.172; cc_entrypoint=cli; cch=8007c;"},
            {"type": "text", "text": "You are Claude Code, Anthropic's official CLI for Claude."},
            {"type": "text", "text": "You are naming a coding session so the user can pick it out of a long list."}
        ])
    }

    fn naming(body: &Value) -> AgentDeclaration {
        declare(&DeclarationSource {
            headers: Some(&headers(&[("x-claude-code-request-class", "auxiliary")])),
            connection_headers: None,
            body: Some(body),
            client_metadata: None,
        })
    }

    #[test]
    fn naming_call_is_a_session_title_call() {
        assert_eq!(
            naming(&naming_body(&naming_system())).purpose,
            Some(EventPurpose::SessionTitle)
        );
    }

    #[test]
    fn naming_instruction_outside_a_claude_code_system_prompt_is_not_a_naming_call() {
        let quoted_by_user = json!({
            "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.293.af3;"}],
            "messages": [{"role": "user", "content": "Why does it say You are naming a coding session?"}]
        });
        let other_client = naming_body(&json!("You are naming a coding session."));

        for body in [quoted_by_user, other_client] {
            assert!(naming(&body).purpose.is_none());
        }
    }
}
