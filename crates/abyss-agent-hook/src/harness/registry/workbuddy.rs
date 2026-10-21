//! `WorkBuddy` user-turn declarations from ordinary HTTP requests.
//! Identity remains policy-configured; these headers do not identify a Harness.

use crate::harness::{AgentDeclaration, DeclarationSource};

use super::header;

pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    let header = |name| source.headers.and_then(|headers| header(headers, name));
    AgentDeclaration {
        // WorkBuddy retains this ID across model calls within one user turn.
        // Message IDs and transport request IDs have a different lifetime.
        turn_id: header("x-conversation-request-id").map(str::to_owned),
        ..AgentDeclaration::default()
    }
}

#[cfg(test)]
mod tests {
    use http::{HeaderMap, HeaderName, HeaderValue};

    use crate::harness::{AgentDeclaration, DeclarationSource, HarnessId, HarnessRegistry};

    fn declared(harness: &str, pairs: &[(&str, &str)]) -> AgentDeclaration {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        HarnessRegistry::declare(
            &serde_json::from_value::<HarnessId>(serde_json::json!(harness)).unwrap(),
            &DeclarationSource {
                headers: Some(&headers),
                body: None,
                client_metadata: None,
                response_texts: &[],
            },
        )
    }

    #[test]
    fn user_turn_is_independent_of_session_and_message_ids() {
        for turn in ["turn-1", "turn-2"] {
            for message in ["model-call-1", "model-call-2"] {
                let declaration = declared(
                    "workbuddy",
                    &[
                        ("X-Conversation-ID", " session-1 "),
                        ("X-Conversation-Request-ID", turn),
                        ("X-Conversation-Message-ID", message),
                        ("X-Request-ID", message),
                    ],
                );
                assert_eq!(declaration.turn_id.as_deref(), Some(turn));
                assert!(declaration.stream_id.is_none());
            }
        }
    }

    #[test]
    fn missing_and_blank_ids_do_not_invent_correlation() {
        for pairs in [
            vec![],
            vec![
                ("x-conversation-id", " \t"),
                ("x-conversation-request-id", ""),
            ],
            vec![
                ("x-request-id", "request-1"),
                ("x-conversation-message-id", "message-1"),
            ],
        ] {
            assert_eq!(declared("workbuddy", &pairs), AgentDeclaration::default());
        }
        let session_only = declared("workbuddy", &[("x-conversation-id", "session-1")]);
        assert_eq!(session_only, AgentDeclaration::default());
        let turn_only = declared("workbuddy", &[("x-conversation-request-id", " turn-1 ")]);
        assert_eq!(turn_only.turn_id.as_deref(), Some("turn-1"));
    }

    #[test]
    fn turn_header_does_not_declare_turns_for_other_harnesses() {
        for harness in ["codex", "claude-code", "deepseek-harness", "custom-client"] {
            assert_eq!(
                declared(
                    harness,
                    &[
                        ("x-conversation-id", "session-1"),
                        ("x-conversation-request-id", "turn-1")
                    ]
                ),
                AgentDeclaration::default(),
                "{harness}"
            );
        }
    }
}
