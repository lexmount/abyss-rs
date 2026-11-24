//! Built-in and configured Harness detection over generic request metadata.

mod chatgpt;
mod claude_code;
mod claude_desktop;
mod codex;
mod cursor;
mod deepseek_harness;
mod hermes;
mod opencode;
mod workbuddy;

use abyss_mitm::{FlowContext, HttpExchange, WebSocketMessage};
use http::{HeaderMap, Method, Request, Uri};

use crate::{config::HarnessUsageConfig, http_metadata::header};

use super::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessId,
    matcher::HarnessMatcher,
};

/// Borrowed transport metadata available to HTTP and WebSocket detectors.
pub(super) struct HarnessRequest<'a> {
    flow: &'a FlowContext,
    method: &'a Method,
    uri: &'a Uri,
    headers: &'a HeaderMap,
}

/// Signing identifiers that each name exactly one built-in Harness. The
/// platform verifies them against the developer's signature, so they identify
/// the program however it was installed or launched.
const SIGNED_APPLICATIONS: [(&str, BuiltInHarness); 3] = [
    (
        "com.anthropic.claudefordesktop",
        BuiltInHarness::ClaudeDesktop,
    ),
    (
        "com.anthropic.claudefordesktop.helper",
        BuiltInHarness::ClaudeDesktop,
    ),
    ("com.anthropic.claude-code", BuiltInHarness::ClaudeCode),
];

impl<'a> HarnessRequest<'a> {
    fn new<B>(flow: &'a FlowContext, request: &'a Request<B>) -> Self {
        Self {
            flow,
            method: request.method(),
            uri: request.uri(),
            headers: request.headers(),
        }
    }

    /// Built-in Harness the source process's signing identifier names.
    fn signed_harness(&self) -> Option<BuiltInHarness> {
        let application_id = self
            .flow
            .source_process
            .as_ref()?
            .application_id
            .as_deref()?;
        SIGNED_APPLICATIONS
            .iter()
            .find(|(id, _)| *id == application_id)
            .map(|(_, harness)| *harness)
    }

    /// Whether the source process's signing identifier names `harness`.
    fn signed_as(&self, harness: BuiltInHarness) -> bool {
        self.signed_harness()
            .is_some_and(|signed| signed.id() == harness.id())
    }
}

/// Product-owned Harness recognition over generic flow and request metadata.
pub(super) trait HarnessDetector {
    fn detect(&self, request: &HarnessRequest<'_>) -> Option<HarnessDetection>;
}

/// Stateless detector registry evaluated against the current policy snapshot.
pub struct HarnessRegistry;

impl HarnessRegistry {
    pub fn detect_http(
        exchange: &HttpExchange,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        Self::recognize_request(&exchange.flow, &exchange.request, config, true)
    }

    pub fn detect_websocket(
        message: &WebSocketMessage,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        Self::recognize_request(&message.flow, &message.upgrade_request, config, true)
    }

    /// Recognition can be reused independently of observation enablement.
    pub(crate) fn recognize_request<B>(
        flow: &FlowContext,
        request: &Request<B>,
        config: &HarnessUsageConfig,
        apply_audit_policy: bool,
    ) -> Option<HarnessDetection> {
        let request = HarnessRequest::new(flow, request);
        let detectors: [&dyn HarnessDetector; 9] = [
            &chatgpt::ChatGptDetector,
            &codex::CodexDetector,
            &claude_desktop::ClaudeDesktopDetector,
            &claude_code::ClaudeCodeDetector,
            &deepseek_harness::DeepSeekHarnessDetector,
            &hermes::HermesDetector,
            &cursor::CursorDetector,
            &workbuddy::WorkBuddyDetector,
            &opencode::OpenCodeDetector,
        ];
        let enabled = |detection: &HarnessDetection| {
            !apply_audit_policy || config.enabled_for_harness(detection.harness_id.as_str())
        };
        let mut detections: Vec<_> = detectors
            .iter()
            .filter_map(|detector| detector.detect(&request))
            .collect();

        // A signing identifier settles the client before request markers,
        // detector order, or policy, so disabling it cannot relabel its traffic.
        if let Some(signed) = request.signed_harness() {
            detections.retain(|detection| detection.harness_id.as_str() == signed.id());
        }

        // Hermes can send Codex/Claude compatibility fingerprints.
        // Apply their explicit identity before policy filtering so disabling
        // one cannot relabel its traffic as the impersonated client.
        if detections
            .iter()
            .any(|detection| detection.harness_id.as_str() == "hermes")
        {
            detections.retain(|detection| {
                !matches!(detection.harness_id.as_str(), "codex" | "claude-code")
            });
        }
        detections.retain(enabled);

        for (harness_id, harness) in &config.harnesses {
            if harness_id.is_reserved() || (apply_audit_policy && !harness.enabled.unwrap_or(true))
            {
                continue;
            }
            if harness
                .matchers
                .iter()
                .any(|matcher| HarnessMatcher::new(matcher).matches(flow))
            {
                detections.push(HarnessDetection {
                    harness_id: harness_id.clone(),
                    version: None,
                });
            }
        }

        detections.into_iter().next()
    }
}

impl HarnessRegistry {
    /// Reads what the detected Agent declares about a request. Agents without
    /// supported declarations declare nothing.
    #[must_use]
    pub fn declare(harness_id: &HarnessId, source: &DeclarationSource<'_>) -> AgentDeclaration {
        match harness_id.as_str() {
            id if id == BuiltInHarness::Codex.id() => codex::declare(source),
            id if id == BuiltInHarness::ClaudeCode.id() => claude_code::declare(source),
            id if id == BuiltInHarness::Hermes.id() => hermes::declare(source),
            id if id == BuiltInHarness::Cursor.id() => cursor::declare(source),
            id if id == BuiltInHarness::WorkBuddy.id() => workbuddy::declare(source),
            id if id == BuiltInHarness::OpenCode.id() => opencode::declare(source),
            _ => AgentDeclaration::default(),
        }
    }
}

fn client_version(user_agent: &str, prefixes: &[&str]) -> Option<String> {
    user_agent.split([' ', ';', ')', '(']).find_map(|token| {
        let normalized = token.to_ascii_lowercase();
        prefixes.iter().find_map(|prefix| {
            normalized
                .strip_prefix(prefix)
                .filter(|version| !version.is_empty())
                .map(str::to_owned)
        })
    })
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, SourceProcess,
        TransparentProtocol, WebSocketDirection, WebSocketMessage,
    };
    use http::{Request, Response};

    use crate::config::HarnessUsageConfig;

    use super::HarnessRegistry;

    #[test]
    fn codex_backend_does_not_identify_http_or_websocket_callers() {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            None,
        );
        let config = HarnessUsageConfig::default();
        for (headers, expected) in [
            (vec![], None),
            // A generic Pi client is not identified by the Codex backend.
            (
                vec![("user-agent", "pi (darwin; arm64)"), ("originator", "pi")],
                None,
            ),
            (
                vec![
                    ("user-agent", "HermesAgent/0.22.0"),
                    ("originator", "hermes-agent"),
                ],
                Some("hermes"),
            ),
            // Hermes retains Codex compatibility headers for custom backends.
            (
                vec![
                    ("user-agent", "codex_cli_rs/0.0.0 (Hermes Agent)"),
                    ("originator", "codex_cli_rs"),
                ],
                Some("hermes"),
            ),
            (
                vec![
                    ("user-agent", "codex_cli_rs/0.1.0"),
                    ("originator", "codex_cli_rs"),
                    ("x-hermes-session-id", "session-1"),
                ],
                Some("hermes"),
            ),
            (vec![("user-agent", "another-codex-client/1.0")], None),
            (vec![("originator", "my-codex-proxy")], None),
            (
                vec![("user-agent", "deepseek-harness/0.2.0")],
                Some("deepseek-harness"),
            ),
            (
                vec![("user-agent", "codex_cli_rs/0.1.0 (Mac OS)")],
                Some("codex"),
            ),
            (vec![("originator", "codex_exec")], Some("codex")),
            (vec![("x-codex-turn-metadata", "{}")], Some("codex")),
        ] {
            for path in ["/backend-api/codex/responses", "/v1/responses"] {
                let mut request = Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("host", "chatgpt.com");
                for (name, value) in &headers {
                    request = request.header(*name, *value);
                }
                let exchange = HttpExchange::new(
                    flow.clone(),
                    request.body(CapturedBody::from_bytes("{}".into())).unwrap(),
                    Response::new(CapturedBody::from_bytes("{}".into())),
                );
                let detected = HarnessRegistry::detect_http(&exchange, &config);
                assert_eq!(
                    detected
                        .as_ref()
                        .map(|detection| detection.harness_id.as_str()),
                    expected,
                    "HTTP {path} {headers:?}",
                );

                let (mut parts, _) = exchange.request.into_parts();
                parts.method = http::Method::GET;
                let message = WebSocketMessage::new(
                    flow.clone(),
                    Request::from_parts(parts, ()),
                    Response::builder().status(101).body(()).unwrap(),
                    WebSocketDirection::ClientToServer,
                    1,
                    Some("{}".to_owned()),
                    None,
                );
                let detected = HarnessRegistry::detect_websocket(&message, &config);
                assert_eq!(
                    detected
                        .as_ref()
                        .map(|detection| detection.harness_id.as_str()),
                    expected,
                    "WebSocket {path} {headers:?}",
                );
            }
        }
    }

    #[test]
    fn deepseek_is_builtin_and_requires_its_user_agent_prefix() {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            None,
        );
        let config = HarnessUsageConfig::default();
        for (user_agent, expected) in [
            (Some("deepseek-harness/0.2.0-rc.2"), true),
            (Some("deepseek-harness/0.2.0-rc.2 (node)"), true),
            (Some("unrelated deepseek-harness/0.2.0-rc.2"), false),
            (Some("deepseek-harness-other/0.2.0-rc.2"), false),
            (Some("DEEPSEEK-HARNESS/0.2.0-rc.2"), false),
            (None, false),
        ] {
            let mut request = Request::post("/responses").body(()).unwrap();
            if let Some(value) = user_agent {
                request
                    .headers_mut()
                    .insert("user-agent", value.parse().unwrap());
            }
            let detected = HarnessRegistry::recognize_request(&flow, &request, &config, true);
            assert_eq!(detected.is_some(), expected, "{user_agent:?}");
            if let Some(detected) = detected {
                assert_eq!(detected.harness_id.as_str(), "deepseek-harness");
                assert_eq!(detected.version.as_deref(), Some("0.2.0-rc.2"));
            }
        }

        let mut request = Request::post("/responses").body(()).unwrap();
        request
            .headers_mut()
            .insert("user-agent", "deepseek-harness/0.2.0-rc.2".parse().unwrap());
        let disabled = serde_json::from_value::<HarnessUsageConfig>(serde_json::json!({
            "harnesses": {"deepseek-harness": {"enabled": false}}
        }))
        .unwrap();
        assert!(HarnessRegistry::recognize_request(&flow, &request, &disabled, true).is_none());

        // Codex is the first matching detector, even with another client's marker.
        request
            .headers_mut()
            .insert("x-codex-turn-metadata", "{}".parse().unwrap());
        assert_eq!(
            HarnessRegistry::recognize_request(&flow, &request, &config, true)
                .unwrap()
                .harness_id
                .as_str(),
            "codex"
        );
        let disabled = serde_json::from_value::<HarnessUsageConfig>(serde_json::json!({
            "harnesses": {"codex": {"enabled": false}}
        }))
        .unwrap();
        assert_eq!(
            HarnessRegistry::recognize_request(&flow, &request, &disabled, true)
                .unwrap()
                .harness_id
                .as_str(),
            "deepseek-harness"
        );
    }

    #[test]
    fn desktop_chat_and_codex_share_a_helper_but_obey_independent_audit_policies() {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(
                SourceProcess::new(None, Some("codex".to_owned()), None)
                    .with_application_id(Some("com.openai.codex.helper".to_owned())),
            ),
        );
        for (method, url, expected) in [
            (
                "POST",
                "https://chatgpt.com/backend-api/f/conversation",
                "chatgpt",
            ),
            (
                "POST",
                "https://chat.openai.com/backend-api/conversation/?test=1",
                "chatgpt",
            ),
            (
                "POST",
                "https://chatgpt.com/backend-api/codex/responses",
                "codex",
            ),
            (
                "GET",
                "https://chatgpt.com/backend-api/f/conversation",
                "codex",
            ),
            (
                "POST",
                "https://gateway.example/backend-api/f/conversation",
                "codex",
            ),
        ] {
            let request = http::Request::builder()
                .method(method)
                .uri(url)
                .header("originator", "codex_cli_rs")
                .body(())
                .unwrap();
            for (chat, codex) in [(true, true), (false, true), (true, false), (false, false)] {
                let config = serde_json::from_value(serde_json::json!({
                    "harnesses": {
                        "chatgpt": { "enabled": chat },
                        "codex": { "enabled": codex },
                        "custom-desktop": { "matchers": [{ "process_names": ["codex"] }] }
                    }
                }))
                .unwrap();
                let recognized =
                    HarnessRegistry::recognize_request(&flow, &request, &config, false).unwrap();
                assert_eq!(recognized.harness_id.as_str(), expected);
                let observed = HarnessRegistry::recognize_request(&flow, &request, &config, true);
                let expected_observed = match (expected, chat, codex) {
                    ("chatgpt", true, _) => Some("chatgpt"),
                    ("codex", _, true) => Some("codex"),
                    _ => Some("custom-desktop"),
                };
                assert_eq!(
                    observed.as_ref().map(|d| d.harness_id.as_str()),
                    expected_observed,
                    "{method} {url} with chat={chat} and codex={codex}"
                );
            }
        }
    }

    #[test]
    fn desktop_chat_source_is_independent_of_the_conversation_wire_format() {
        let request = Request::post("https://chatgpt.com/backend-api/f/conversation")
            .header("originator", "codex_cli_rs")
            .body(())
            .unwrap();
        let config = HarnessUsageConfig::default();
        for (name, expected) in [("CHATGPT.EXE", Some("chatgpt")), ("chrome.exe", None)] {
            let flow = FlowContext::from_optional_addrs(
                None,
                None,
                OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                TransparentProtocol::PlainHttp,
                Some(SourceProcess::new(None, Some(name.to_owned()), None)),
            );
            let detection = HarnessRegistry::recognize_request(&flow, &request, &config, true);
            assert_eq!(detection.as_ref().map(|d| d.harness_id.as_str()), expected);
        }
    }

    #[test]
    fn custom_harnesses_use_first_enabled_match_in_id_order() {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(SourceProcess::new(
                None,
                Some("custom-agent".to_owned()),
                None,
            )),
        );
        for enabled in [true, false] {
            // Definition order does not override the map's deterministic ID order.
            let config = serde_json::from_value::<HarnessUsageConfig>(serde_json::json!({
                "harnesses": {
                    "z-client": {"matchers": [{"process_names": ["custom-agent"]}]},
                    "a-client": {
                        "enabled": enabled,
                        "matchers": [{"process_names": ["custom-agent"]}]
                    }
                }
            }))
            .unwrap();
            let request = Request::post("/v1/messages").body(()).unwrap();
            let detection = HarnessRegistry::recognize_request(&flow, &request, &config, true);
            assert_eq!(
                detection.as_ref().map(|item| item.harness_id.as_str()),
                Some(if enabled { "a-client" } else { "z-client" })
            );
            assert_eq!(
                HarnessRegistry::recognize_request(&flow, &request, &config, false)
                    .unwrap()
                    .harness_id
                    .as_str(),
                "a-client"
            );
        }
    }

    #[test]
    fn claude_web_route_alone_does_not_identify_claude_desktop() {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            None,
        );

        assert!(
            HarnessRegistry::recognize_request(
                &flow,
                &Request::post(
                    "/api/organizations/org-id/chat_conversations/conversation-id/completion"
                )
                .body(())
                .unwrap(),
                &HarnessUsageConfig::default(),
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn claude_inspection_identity_is_independent_of_audit_enablement() {
        let mut flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            None,
        );
        let config = serde_json::from_value::<HarnessUsageConfig>(serde_json::json!({
            "harnesses": {
                "claude-desktop": {"enabled": false},
                "claude-code": {"enabled": false}
            }
        }))
        .unwrap();
        let mut request = Request::post("/v1/messages").body(()).unwrap();
        request
            .headers_mut()
            .insert("user-agent", "claude/1.0.0".parse().unwrap());
        for (name, expected) in [
            ("Claude Helper", "claude-desktop"),
            ("claude", "claude-code"),
        ] {
            flow.source_process = Some(SourceProcess::new(None, Some(name.to_owned()), None));
            assert!(HarnessRegistry::recognize_request(&flow, &request, &config, true).is_none());
            let detected =
                HarnessRegistry::recognize_request(&flow, &request, &config, false).unwrap();
            assert_eq!(detected.harness_id.as_str(), expected);
        }
    }

    #[test]
    fn claude_signing_identifiers_identify_without_other_markers() {
        let config = HarnessUsageConfig::default();
        let request = Request::post("/v1/messages").body(()).unwrap();
        for (application_id, expected) in [
            ("com.anthropic.claudefordesktop", "claude-desktop"),
            ("com.anthropic.claudefordesktop.helper", "claude-desktop"),
            ("com.anthropic.claude-code", "claude-code"),
        ] {
            let flow = FlowContext::from_optional_addrs(
                None,
                None,
                OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
                TransparentProtocol::PlainHttp,
                Some(
                    SourceProcess::new(None, None, None)
                        .with_application_id(Some(application_id.to_owned())),
                ),
            );
            let detected =
                HarnessRegistry::recognize_request(&flow, &request, &config, true).unwrap();
            assert_eq!(detected.harness_id.as_str(), expected, "{application_id}");
        }
    }
}
