//! Codex detection from product-owned process and request markers, and what
//! Codex declares about a request: the request kind and root turn in its
//! `x-codex-turn-metadata`, and the subagent thread in its thread headers.
//! Backend routes select a protocol, never the identity of its caller.

use abyss_mitm::FlowContext;
use abyss_plugin_protocol::event::EventPurpose;
use http::HeaderMap;
use serde_json::Value;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessId,
};

use super::{HarnessDetector, client_version, header};

/// Header and `client_metadata` key carrying Codex turn context as JSON.
const TURN_METADATA: &str = "x-codex-turn-metadata";
/// `request_kind` of a request that summarizes the conversation.
const COMPACTION_REQUEST_KIND: &str = "compaction";
/// Thread the request belongs to.
const THREAD_ID: &str = "thread-id";
/// Thread that spawned the request's thread; only a subagent thread names one.
const PARENT_THREAD_ID: &str = "x-codex-parent-thread-id";
/// Codex session, whose id is also its main thread's.
const SESSION_ID: &str = "session-id";

/// Reads the turn metadata a request carries in its `client_metadata`, or for
/// HTTP requests in the header of the same name, and the subagent thread its
/// headers name, or for a WebSocket turn its connection's.
pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    let metadata = source
        .client_metadata
        .and_then(|client| string_field(client, TURN_METADATA))
        .or_else(|| {
            source
                .headers
                .and_then(|headers| header(headers, TURN_METADATA))
        })
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .filter(Value::is_object);
    let thread = |name: &str| {
        source
            .request_or_connection_headers()
            .and_then(|headers| header(headers, name))
    };
    // Only a subagent thread names a parent; a parent that is the session is
    // the main thread.
    let parent = thread(PARENT_THREAD_ID);
    AgentDeclaration {
        purpose: metadata
            .as_ref()
            .and_then(|metadata| string_field(metadata, "request_kind"))
            .filter(|kind| *kind == COMPACTION_REQUEST_KIND)
            .map(|_| EventPurpose::Compaction),
        subagent_id: parent.and_then(|_| thread(THREAD_ID)).map(str::to_owned),
        parent_subagent_id: parent
            .filter(|parent| thread(SESSION_ID) != Some(*parent))
            .map(str::to_owned),
        turn_id: metadata
            .as_ref()
            .and_then(|metadata| string_field(metadata, "root_turn_id"))
            .map(str::to_owned),
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
        _path: &str,
    ) -> Option<HarnessDetection> {
        let user_agent = header(headers, "user-agent").unwrap_or_default();
        let originator = header(headers, "originator").unwrap_or_default();
        let process = flow
            .source_process
            .as_ref()
            .and_then(|process| process.name.as_deref())
            .is_some_and(|name| normalize(name) == "codex");
        let marked = headers
            .keys()
            .any(|name| name.as_str().to_ascii_lowercase().starts_with("x-codex-"))
            || Self::is_codex_client(user_agent.split('/').next().unwrap_or_default())
            || Self::is_codex_client(originator);
        if !process && !marked {
            return None;
        }
        Some(HarnessDetection {
            harness_id: HarnessId::from(BuiltInHarness::Codex),
            version: client_version(user_agent, &["codex/tui/", "codex/desktop/", "codex/"]),
        })
    }
}

impl CodexDetector {
    fn is_codex_client(name: &str) -> bool {
        let name = name.to_ascii_lowercase();
        matches!(
            name.as_str(),
            "codex"
                | "codex_cli_rs"
                | "codex-tui"
                | "codex_vscode"
                | "codex_exec"
                | "codex_atlas"
                | "codex_chatgpt_desktop"
        ) || name.starts_with("codex ")
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
    use std::net::SocketAddr;

    use abyss_mitm::{FlowContext, OriginalDestination, SourceProcess, TransparentProtocol};
    use abyss_plugin_protocol::event::EventPurpose;
    use http::HeaderMap;
    use serde_json::{Value, json};

    use crate::harness::{AgentDeclaration, DeclarationSource};

    use super::{CodexDetector, HarnessDetector, declare};

    #[test]
    fn detection_records_client_headers_and_process_instead_of_backend_path() {
        let mut flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            None,
        );
        for (name, value) in [
            ("user-agent", "codex/tui/1.2.3"),
            ("user-agent", "codex/desktop/1.2.3"),
            ("user-agent", "codex_cli_rs/1.2.3 (Mac OS)"),
            ("user-agent", "codex-tui/1.2.3"),
            ("user-agent", "codex_vscode/1.2.3"),
            ("user-agent", "Codex Desktop/1.2.3"),
            ("originator", "codex_cli_rs"),
            ("originator", "codex_exec"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(name, value.parse().unwrap());
            let detection = CodexDetector
                .detect(&flow, &headers, "/v1/responses")
                .unwrap_or_else(|| panic!("{name}: {value}"));
            assert_eq!(detection.harness_id.as_str(), "codex");
        }

        flow.source_process = Some(SourceProcess::new(
            None,
            Some("/usr/local/bin/codex".to_owned()),
            None,
        ));
        let detection = CodexDetector
            .detect(&flow, &HeaderMap::new(), "/v1/responses")
            .unwrap();
        assert_eq!(detection.harness_id.as_str(), "codex");
    }

    fn declared(client_metadata: Option<&Value>, headers: Option<&HeaderMap>) -> AgentDeclaration {
        declare(&DeclarationSource {
            headers,
            connection_headers: None,
            client_metadata,
        })
    }

    /// `client_metadata` carrying `metadata` the way Codex does: as a JSON
    /// string, beside top-level copies of some keys.
    fn client_metadata(metadata: &Value) -> Value {
        json!({"turn_id": metadata["turn_id"], "x-codex-turn-metadata": metadata.to_string()})
    }

    #[test]
    fn request_kind_names_compaction() {
        for (metadata, purpose) in [
            (
                json!({"session_id": "session-1", "thread_id": "session-1",
                    "turn_id": "turn-a", "root_turn_id": "turn-a",
                    "thread_source": "user", "request_kind": "turn"}),
                None,
            ),
            (
                json!({"session_id": "session-1", "thread_id": "session-1",
                    "turn_id": "turn-b", "root_turn_id": "turn-b",
                    "thread_source": "user", "request_kind": "compaction",
                    "compaction": {"trigger": "auto", "phase": "mid_turn"}}),
                Some(EventPurpose::Compaction),
            ),
        ] {
            let declaration = declared(Some(&client_metadata(&metadata)), None);

            assert_eq!(declaration.purpose, purpose, "{metadata}");
        }
    }

    #[test]
    fn turn_metadata_is_read_from_the_header_without_client_metadata() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-codex-turn-metadata",
            json!({"thread_id": "session-1", "request_kind": "compaction"})
                .to_string()
                .parse()
                .unwrap(),
        );

        let declaration = declared(None, Some(&headers));

        assert_eq!(declaration.purpose, Some(EventPurpose::Compaction));
    }

    fn header_map(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, value.parse().unwrap());
        }
        headers
    }

    /// `(subagent_id, parent_subagent_id, turn_id)` of a declaration.
    fn lineage(declaration: AgentDeclaration) -> [Option<String>; 3] {
        [
            declaration.subagent_id,
            declaration.parent_subagent_id,
            declaration.turn_id,
        ]
    }

    fn ids(values: [Option<&str>; 3]) -> [Option<String>; 3] {
        values.map(|value| value.map(str::to_owned))
    }

    #[test]
    fn a_parent_thread_declares_a_subagent_thread() {
        let metadata =
            json!({"session_id": "s-1", "turn_id": "turn-2", "root_turn_id": "turn-1"}).to_string();
        // The main thread is the session and names no parent.
        let main = header_map(&[
            ("session-id", "s-1"),
            ("thread-id", "s-1"),
            ("x-codex-turn-metadata", &metadata),
        ]);
        assert_eq!(
            lineage(declared(None, Some(&main))),
            ids([None, None, Some("turn-1")])
        );
        // Spawned by the main thread: the parent is the session.
        let spawned = header_map(&[
            ("session-id", "s-1"),
            ("thread-id", "t-2"),
            ("x-codex-parent-thread-id", "s-1"),
            ("x-codex-turn-metadata", &metadata),
        ]);
        assert_eq!(
            lineage(declared(None, Some(&spawned))),
            ids([Some("t-2"), None, Some("turn-1")])
        );
        // Spawned by another subagent thread.
        let nested = header_map(&[
            ("session-id", "s-1"),
            ("thread-id", "t-3"),
            ("x-codex-parent-thread-id", "t-2"),
        ]);
        assert_eq!(
            lineage(declared(None, Some(&nested))),
            ids([Some("t-3"), Some("t-2"), None])
        );
    }

    #[test]
    fn a_websocket_turn_takes_its_thread_from_the_upgrade_and_its_turn_from_the_frame() {
        let upgrade = header_map(&[
            ("session-id", "s-1"),
            ("thread-id", "t-2"),
            ("x-codex-parent-thread-id", "s-1"),
            // The upgrade's own turn metadata is not the frame's turn.
            ("x-codex-turn-metadata", r#"{"root_turn_id":"turn-0"}"#),
        ]);
        let frame = client_metadata(&json!({"turn_id": "turn-3", "root_turn_id": "turn-1"}));
        let declaration = declare(&DeclarationSource {
            headers: None,
            connection_headers: Some(&upgrade),
            client_metadata: Some(&frame),
        });
        assert_eq!(
            lineage(declaration),
            ids([Some("t-2"), None, Some("turn-1")])
        );
        let without_frame = declare(&DeclarationSource {
            headers: None,
            connection_headers: Some(&upgrade),
            client_metadata: None,
        });
        assert_eq!(lineage(without_frame), ids([Some("t-2"), None, None]));
    }

    #[test]
    fn a_root_turn_needs_a_string_in_a_json_object() {
        for metadata in [
            "not json",
            r#"["turn-1"]"#,
            r#"{"turn_id":"turn-1"}"#,
            r#"{"root_turn_id":7}"#,
            r#"{"root_turn_id":""}"#,
        ] {
            let headers = header_map(&[("x-codex-turn-metadata", metadata)]);
            assert_eq!(
                lineage(declared(None, Some(&headers))),
                ids([None, None, None]),
                "{metadata}"
            );
        }
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
