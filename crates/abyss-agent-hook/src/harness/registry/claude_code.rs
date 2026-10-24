//! Claude Code detection from process identity and product request markers,
//! and what Claude Code declares about each request in its
//! `x-claude-code-*` headers.

use abyss_mitm::SourceProcess;
use abyss_plugin_protocol::event::EventPurpose;
use http::HeaderMap;
use serde::Deserialize;
use serde_json::Value;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
    HarnessId,
};

use super::{HarnessDetector, client_version, header};

/// Kind of request: `main`, `subagent`, `compaction`, `auxiliary`, and others.
const REQUEST_CLASS: &str = "x-claude-code-request-class";
/// Identity of the subagent instance that sent the request.
const AGENT_ID: &str = "x-claude-code-agent-id";
/// The user prompt the request works for; a subagent carries the prompt of
/// the turn that started it.
const PROMPT_ID: &str = "x-claude-code-prompt-id";
/// The Claude Code session.
const SESSION_ID: &str = "x-claude-code-session-id";
/// Line prefix Claude Code writes at the start of its first system block.
const BILLING_HEADER: &str = "x-anthropic-billing-header:";
/// System instruction Claude Code sends when naming the session it runs in.
const NAMING_INSTRUCTION: &str = "You are naming a coding session";

/// Reads the request class, agent, and prompt Claude Code declares in its
/// headers, and recognizes the call that names its session.
pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    let header = |name| source.headers.and_then(|headers| header(headers, name));
    let class = header(REQUEST_CLASS);
    // The main loop runs as the session itself; each subagent instance has
    // its own agent id.
    let stream_id = match class {
        Some("main") => header(SESSION_ID),
        Some("subagent") => header(AGENT_ID),
        _ => None,
    };
    let purpose = if class == Some("compaction") {
        Some(EventPurpose::Compaction)
    } else if source.body.is_some_and(names_session) {
        Some(EventPurpose::SessionTitle)
    } else {
        None
    };
    AgentDeclaration {
        turn_id: header(PROMPT_ID).map(str::to_owned),
        stream_id: stream_id.map(str::to_owned),
        naming_thread: false,
        purpose,
        session_title: (purpose == Some(EventPurpose::SessionTitle))
            .then(|| session_title(source.response_texts))
            .flatten(),
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

#[derive(Deserialize)]
struct SessionTitleAnswer {
    title: String,
}

/// Reads the title from a naming call's reply, which is one `{"title": "…"}`
/// object; any other reply yields none.
fn session_title(response_texts: &[String]) -> Option<String> {
    let [text] = response_texts else {
        return None;
    };
    let answer: SessionTitleAnswer = serde_json::from_str(text.trim()).ok()?;
    let title = answer.title.trim();
    (!title.is_empty()).then(|| title.to_owned())
}

pub(super) struct ClaudeCodeDetector;

impl HarnessDetector for ClaudeCodeDetector {
    fn detect(
        &self,
        source: Option<&SourceProcess>,
        headers: &HeaderMap,
        path: &str,
    ) -> Option<HarnessDetection> {
        if path.contains("/organizations/") && path.ends_with("/completion") {
            return None;
        }
        let mut evidence = Vec::new();
        if let Some(source) = source
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
            working_directory: source.and_then(|source| source.working_directory.clone()),
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
            body: None,
            client_metadata: None,
            response_texts: &[],
        })
    }

    #[test]
    fn request_class_names_the_main_loop_subagents_and_compaction() {
        let main = declared(&[
            ("x-claude-code-session-id", "session-1"),
            ("x-claude-code-request-class", "main"),
            ("x-claude-code-prompt-id", "prompt-1"),
        ]);
        assert_eq!(main.turn_id.as_deref(), Some("prompt-1"));
        // The main loop runs as the session itself.
        assert_eq!(main.stream_id.as_deref(), Some("session-1"));
        assert_eq!(main.purpose, None);

        // Each subagent instance is its own thread serving the prompt that
        // started it.
        for agent in ["agent-a", "agent-b"] {
            let subagent = declared(&[
                ("x-claude-code-session-id", "session-1"),
                ("x-claude-code-request-class", "subagent"),
                ("x-claude-code-agent-id", agent),
                ("x-claude-code-agent-type", "general-purpose"),
                ("x-claude-code-prompt-id", "prompt-1"),
            ]);
            assert_eq!(subagent.turn_id.as_deref(), Some("prompt-1"));
            assert_eq!(subagent.stream_id.as_deref(), Some(agent));
        }

        let compaction = declared(&[
            ("x-claude-code-session-id", "session-1"),
            ("x-claude-code-request-class", "compaction"),
            ("x-claude-code-compaction", "manual"),
        ]);
        assert_eq!(compaction.purpose, Some(EventPurpose::Compaction));
        assert_eq!(compaction.turn_id, None);
        assert_eq!(compaction.stream_id, None);
    }

    #[test]
    fn auxiliary_and_undeclared_requests_declare_nothing() {
        let auxiliary = declared(&[
            ("x-claude-code-session-id", "session-1"),
            ("x-claude-code-request-class", "auxiliary"),
        ]);
        assert_eq!(auxiliary, AgentDeclaration::default());
        assert_eq!(declared(&[]), AgentDeclaration::default());
        // A request class without its agent id names no thread.
        let subagent = declared(&[("x-claude-code-request-class", "subagent")]);
        assert_eq!(subagent.stream_id, None);
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

    fn naming(body: &Value, reply: &str) -> AgentDeclaration {
        declare(&DeclarationSource {
            headers: Some(&headers(&[("x-claude-code-request-class", "auxiliary")])),
            body: Some(body),
            client_metadata: None,
            response_texts: &[reply.to_owned()],
        })
    }

    #[test]
    fn naming_call_carries_its_session_title() {
        let declaration = naming(&naming_body(&naming_system()), r#"{"title": " 登录修复 "}"#);

        assert_eq!(declaration.purpose, Some(EventPurpose::SessionTitle));
        assert_eq!(declaration.session_title.as_deref(), Some("登录修复"));
    }

    #[test]
    fn naming_reply_without_one_title_object_carries_no_title() {
        for reply in [
            "We need a short title",
            r#"Title: {"title": "x"}"#,
            r#"{"title": ""}"#,
            r#"{"name": "x"}"#,
        ] {
            let declaration = naming(&naming_body(&naming_system()), reply);

            assert_eq!(
                declaration.purpose,
                Some(EventPurpose::SessionTitle),
                "{reply}"
            );
            assert!(declaration.session_title.is_none(), "{reply}");
        }
    }

    #[test]
    fn naming_instruction_outside_a_claude_code_system_prompt_is_not_a_naming_call() {
        let quoted_by_user = json!({
            "system": [{"type": "text", "text": "x-anthropic-billing-header: cc_version=2.1.293.af3;"}],
            "messages": [{"role": "user", "content": "Why does it say You are naming a coding session?"}]
        });
        let other_client = naming_body(&json!("You are naming a coding session."));

        for body in [quoted_by_user, other_client] {
            let declaration = naming(&body, r#"{"title": "x"}"#);

            assert!(declaration.purpose.is_none());
            assert!(declaration.session_title.is_none());
        }
    }
}
