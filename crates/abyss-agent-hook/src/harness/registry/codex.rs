//! Codex detection from product-owned process and request markers, and the
//! turn context Codex declares in its `x-codex-turn-metadata`.

use abyss_mitm::FlowContext;
use abyss_plugin_protocol::event::EventPurpose;
use http::HeaderMap;
use serde_json::Value;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
    HarnessId,
};

use super::{HarnessDetector, client_version, header};

/// Header and `client_metadata` key carrying Codex turn context as JSON.
const TURN_METADATA: &str = "x-codex-turn-metadata";
/// `thread_source` of a thread that names another session.
const NAMING_THREAD_SOURCE: &str = "thread_title";
/// `request_kind` of a request that summarizes the conversation.
const COMPACTION_REQUEST_KIND: &str = "compaction";

/// Reads the turn metadata a request carries in its `client_metadata`, or for
/// HTTP requests in the header of the same name.
pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    let Some(metadata) = source
        .client_metadata
        .and_then(|client| string_field(client, TURN_METADATA))
        .or_else(|| {
            source
                .headers
                .and_then(|headers| header(headers, TURN_METADATA))
        })
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(Value::is_object)
    else {
        return AgentDeclaration::default();
    };
    let field = |key| string_field(&metadata, key).map(str::to_owned);
    AgentDeclaration {
        // A guardian thread shares `root_turn_id` with the turn it reviews.
        turn_id: field("root_turn_id"),
        // The main thread and a guardian differ in `thread_id`.
        stream_id: field("thread_id"),
        naming_thread: string_field(&metadata, "thread_source") == Some(NAMING_THREAD_SOURCE),
        purpose: (string_field(&metadata, "request_kind") == Some(COMPACTION_REQUEST_KIND))
            .then_some(EventPurpose::Compaction),
        session_title: None,
    }
}

fn string_field<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(super) struct CodexDetector;

impl HarnessDetector for CodexDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
    ) -> Option<HarnessDetection> {
        let mut evidence = Vec::new();
        if let Some(process) = flow.source_process.as_ref()
            && process
                .name
                .as_deref()
                .is_some_and(|name| normalize(name) == "codex")
        {
            evidence.push(HarnessEvidence::Process(
                process.name.clone().unwrap_or_default(),
            ));
        }
        if headers
            .keys()
            .any(|name| name.as_str().to_ascii_lowercase().starts_with("x-codex-"))
        {
            evidence.push(HarnessEvidence::Header("x-codex-*"));
        }
        let user_agent = header(headers, "user-agent").unwrap_or_default();
        let originator = header(headers, "originator").unwrap_or_default();
        if format!("{path} {user_agent} {originator}")
            .to_ascii_lowercase()
            .contains("codex")
        {
            evidence.push(HarnessEvidence::Path(path.to_owned()));
        }
        if evidence.is_empty() {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::Codex),
            evidence,
            version: client_version(user_agent, &["codex/tui/", "codex/desktop/", "codex/"]),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

fn normalize(value: &str) -> String {
    value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .trim()
        .to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::event::EventPurpose;
    use http::HeaderMap;
    use serde_json::{Value, json};

    use crate::harness::{AgentDeclaration, DeclarationSource};

    use super::declare;

    fn declared(client_metadata: Option<&Value>, headers: Option<&HeaderMap>) -> AgentDeclaration {
        declare(&DeclarationSource {
            headers,
            body: None,
            client_metadata,
            response_texts: &[],
        })
    }

    /// `client_metadata` carrying `metadata` the way Codex does: as a JSON
    /// string, beside top-level copies of some keys.
    fn client_metadata(metadata: &Value) -> Value {
        json!({"turn_id": metadata["turn_id"], "x-codex-turn-metadata": metadata.to_string()})
    }

    #[test]
    fn turn_metadata_names_the_user_turn_thread_naming_threads_and_compaction() {
        for (metadata, turn_id, stream_id, naming_thread, purpose) in [
            (
                json!({"session_id": "session-1", "thread_id": "session-1",
                    "turn_id": "turn-a", "root_turn_id": "turn-a",
                    "thread_source": "user", "request_kind": "turn"}),
                Some("turn-a"),
                Some("session-1"),
                false,
                None,
            ),
            // A guardian thread reviews the user turn it was opened for.
            (
                json!({"session_id": "session-1", "thread_id": "thread-g",
                    "parent_thread_id": "session-1", "turn_id": "turn-g",
                    "parent_turn_id": "turn-a", "root_turn_id": "turn-a",
                    "subagent_kind": "guardian", "thread_source": "guardian_review",
                    "request_kind": "turn"}),
                Some("turn-a"),
                Some("thread-g"),
                false,
                None,
            ),
            (
                json!({"session_id": "session-1", "thread_id": "session-1",
                    "turn_id": "turn-b", "root_turn_id": "turn-b",
                    "thread_source": "user", "request_kind": "compaction",
                    "compaction": {"trigger": "auto", "phase": "mid_turn"}}),
                Some("turn-b"),
                Some("session-1"),
                false,
                Some(EventPurpose::Compaction),
            ),
            (
                json!({"session_id": "naming-1", "thread_id": "naming-1",
                    "turn_id": "turn-t", "root_turn_id": "turn-t",
                    "thread_source": "thread_title", "request_kind": "turn"}),
                Some("turn-t"),
                Some("naming-1"),
                true,
                None,
            ),
            // Only the root turn names the user turn.
            (
                json!({"turn_id": "turn-c", "thread_source": "user"}),
                None,
                None,
                false,
                None,
            ),
        ] {
            let declaration = declared(Some(&client_metadata(&metadata)), None);

            assert_eq!(declaration.turn_id.as_deref(), turn_id, "{metadata}");
            assert_eq!(declaration.stream_id.as_deref(), stream_id, "{metadata}");
            assert_eq!(declaration.naming_thread, naming_thread, "{metadata}");
            assert_eq!(declaration.purpose, purpose, "{metadata}");
        }
    }

    #[test]
    fn turn_metadata_is_read_from_the_header_without_client_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-turn-metadata",
            json!({"thread_id": "naming-1", "turn_id": "turn-g",
                "root_turn_id": "turn-a", "thread_source": "thread_title"})
            .to_string()
            .parse()
            .unwrap(),
        );

        let declaration = declared(None, Some(&headers));

        assert_eq!(declaration.turn_id.as_deref(), Some("turn-a"));
        assert_eq!(declaration.stream_id.as_deref(), Some("naming-1"));
        assert!(declaration.naming_thread);
    }

    #[test]
    fn malformed_or_absent_turn_metadata_declares_nothing() {
        let malformed = json!({"turn_id": "turn-a", "x-codex-turn-metadata": "{broken"});

        assert_eq!(
            declared(Some(&malformed), None),
            AgentDeclaration::default()
        );
        assert_eq!(declared(None, None), AgentDeclaration::default());
    }
}
