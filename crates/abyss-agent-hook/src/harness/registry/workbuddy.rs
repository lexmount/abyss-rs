//! `WorkBuddy` identity from source processes and application IDs, and user-turn
//! declarations. Protocol parsers resolve sessions; correlation headers and
//! provider hosts alone never identify `WorkBuddy`.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
};

use super::{HarnessDetector, header};

// Never include generic Electron, Node, or standalone CodeBuddy processes.
const PROCESS_NAMES: &[&str] = &[
    "WorkBuddy",
    "WorkBuddy Helper",
    "WorkBuddy Helper (GPU)",
    "WorkBuddy Helper (Plugin)",
    "WorkBuddy Helper (Renderer)",
    "WorkBuddy AI Helper",
    "WorkBuddy AI Helper (GPU)",
    "WorkBuddy AI Helper (Plugin)",
    "WorkBuddy AI Helper (Renderer)",
];
const WINDOWS_PROCESS_NAMES: &[&str] = &["WorkBuddy.exe", "WorkBuddyAI.exe"];
const APPLICATION_IDS: &[&str] = &[
    "com.tencent.workbuddy.mac",
    "com.tencent.workbuddy.mac.helper",
    "com.tencent.workbuddy.mac.helper.GPU",
    "com.tencent.workbuddy.mac.helper.Plugin",
    "com.tencent.workbuddy.mac.helper.Renderer",
    "com.workbuddy.workbuddy-ai",
    "com.workbuddy.workbuddy-ai.helper",
    "com.workbuddy.workbuddy-ai.helper.GPU",
    "com.workbuddy.workbuddy-ai.helper.Plugin",
    "com.workbuddy.workbuddy-ai.helper.Renderer",
];

pub(super) struct WorkBuddyDetector;

impl HarnessDetector for WorkBuddyDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        _headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let source = flow.source_process.as_ref()?;
        let evidence = if let Some(application_id) = source
            .application_id
            .as_deref()
            .filter(|id| APPLICATION_IDS.contains(id))
        {
            HarnessEvidence::ApplicationId(application_id.to_owned())
        } else {
            let process = source
                .name
                .as_deref()
                .into_iter()
                .chain(source.executable_path.as_deref())
                .find(|value| {
                    // Platform adapters can provide either a basename or path.
                    value.rsplit(['/', '\\']).next().is_some_and(|name| {
                        PROCESS_NAMES.contains(&name)
                            || WINDOWS_PROCESS_NAMES
                                .iter()
                                .any(|known| name.eq_ignore_ascii_case(known))
                    })
                })?;
            HarnessEvidence::Process(process.to_owned())
        };
        Some(HarnessDetection {
            harness_id: BuiltInHarness::WorkBuddy.into(),
            evidence: vec![evidence],
            version: None,
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

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
    use std::net::SocketAddr;

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, SourceProcess,
        TransparentProtocol, WebSocketDirection, WebSocketMessage,
    };
    use http::{HeaderMap, HeaderName, HeaderValue, Request, Response};
    use serde_json::json;

    use crate::config::HarnessUsageConfig;
    use crate::harness::{AgentDeclaration, DeclarationSource, HarnessId, HarnessRegistry};

    fn assert_identity(source: Option<SourceProcess>, config: &HarnessUsageConfig, expected: bool) {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            source,
        );
        let request = Request::builder()
            .uri("/v2/chat/completions")
            .header("host", "www.workbuddy.cn")
            .header("user-agent", "axios/1.18.1")
            .header("x-conversation-id", "session-1")
            .header("x-conversation-request-id", "turn-1")
            .body(CapturedBody::from_bytes("{}".into()))
            .unwrap();
        let exchange = HttpExchange::new(
            flow.clone(),
            request,
            Response::new(CapturedBody::from_bytes("".into())),
        );
        let detection = HarnessRegistry::detect_http(&exchange, config);
        assert_eq!(
            detection.as_ref().map(|item| item.harness_id.as_str()),
            expected.then_some("workbuddy")
        );
        let (parts, _) = exchange.request.into_parts();
        let message = WebSocketMessage::new(
            flow,
            Request::from_parts(parts, ()),
            Response::builder().status(101).body(()).unwrap(),
            WebSocketDirection::ClientToServer,
            1,
            Some("{}".to_owned()),
            None,
        );
        let detection = HarnessRegistry::detect_websocket(&message, config);
        assert_eq!(
            detection.as_ref().map(|item| item.harness_id.as_str()),
            expected.then_some("workbuddy")
        );
    }

    #[test]
    fn builtin_recognizes_macos_and_windows_without_custom_matchers() {
        let config = HarnessUsageConfig::default();
        for name in [
            "WorkBuddy",
            "WorkBuddy.exe",
            "workbuddy.exe",
            "WorkBuddyAI.exe",
            "workbuddyai.exe",
            "WORKBUDDYAI.EXE",
            r"\device\harddiskvolume4\workbuddy\workbuddyai.exe",
            "WorkBuddy Helper (Renderer)",
            "WorkBuddy AI Helper",
            "WorkBuddy AI Helper (GPU)",
            "WorkBuddy AI Helper (Plugin)",
            "WorkBuddy AI Helper (Renderer)",
            "/Applications/WorkBuddy AI.app/Contents/Frameworks/WorkBuddy AI Helper.app/Contents/MacOS/WorkBuddy AI Helper",
            "/Applications/WorkBuddy.app/Contents/Frameworks/WorkBuddy Helper.app/Contents/MacOS/WorkBuddy Helper",
            "C:\\Program Files\\WorkBuddy\\WorkBuddy.exe",
        ] {
            assert_identity(
                Some(SourceProcess::new(None, Some(name.to_owned()), None)),
                &config,
                true,
            );
            assert_identity(
                Some(SourceProcess::new(None, None, Some(name.to_owned()))),
                &config,
                true,
            );
        }
        for application_id in [
            "com.tencent.workbuddy.mac",
            "com.tencent.workbuddy.mac.helper",
            "com.tencent.workbuddy.mac.helper.GPU",
            "com.tencent.workbuddy.mac.helper.Plugin",
            "com.tencent.workbuddy.mac.helper.Renderer",
            "com.workbuddy.workbuddy-ai",
            "com.workbuddy.workbuddy-ai.helper",
            "com.workbuddy.workbuddy-ai.helper.GPU",
            "com.workbuddy.workbuddy-ai.helper.Plugin",
            "com.workbuddy.workbuddy-ai.helper.Renderer",
        ] {
            assert_identity(
                Some(
                    SourceProcess::new(None, Some("Electron".to_owned()), None)
                        .with_application_id(Some(application_id.to_owned())),
                ),
                &config,
                true,
            );
        }
    }

    #[test]
    fn generic_runtimes_headers_and_lookalikes_do_not_identify_workbuddy() {
        let config = HarnessUsageConfig::default();
        assert_identity(None, &config, false);
        for name in [
            "Electron",
            "node",
            "codebuddy",
            "OtherWorkBuddy",
            "OtherWorkBuddy AI Helper",
            "WorkBuddy AI Helper.bak",
            "workbuddy.exe.bak",
            "WorkBuddyAI.exe.bak",
            "OtherWorkBuddyAI.exe",
            "/Applications/OtherWorkBuddy.app/Contents/MacOS/Electron",
            "C:\\WorkBuddy.exe\\other.exe",
        ] {
            assert_identity(
                Some(SourceProcess::new(None, Some(name.to_owned()), None)),
                &config,
                false,
            );
        }
        for application_id in [
            "com.tencent.workbuddy.mac.unrelated",
            "com.tencent.workbuddy.mac.helper.Other",
            "com.workbuddy.workbuddy-ai.unrelated",
            "com.workbuddy.workbuddy-ai.helper.Other",
        ] {
            assert_identity(
                Some(
                    SourceProcess::new(None, Some("Electron".to_owned()), None)
                        .with_application_id(Some(application_id.to_owned())),
                ),
                &config,
                false,
            );
        }
    }

    #[test]
    fn builtin_respects_disabled_policy_and_ambiguous_custom_identity() {
        for config in [
            json!({"harnesses": {"workbuddy": {"enabled": false}}}),
            json!({"harnesses": {"another-client": {"matchers": [{"process_names": ["WorkBuddy"]}]}}}),
        ] {
            assert_identity(
                Some(SourceProcess::new(None, Some("WorkBuddy".to_owned()), None)),
                &serde_json::from_value(config).unwrap(),
                false,
            );
        }
    }

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
                connection_headers: None,
                body: None,
                client_metadata: None,
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
                assert_eq!(
                    declaration,
                    AgentDeclaration {
                        turn_id: Some(turn.to_owned()),
                        ..AgentDeclaration::default()
                    }
                );
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
