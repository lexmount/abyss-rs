//! Built-in and configured Harness detection over generic request metadata.

mod claude_code;
mod claude_desktop;
mod codex;
mod deepseek_harness;
mod hermes;
mod openclaw;

use abyss_mitm::{FlowContext, HttpExchange, WebSocketMessage};
use http::HeaderMap;

use crate::config::HarnessUsageConfig;

use super::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
    HarnessId, matcher::HarnessMatcher,
};

/// Product-owned Harness recognition over generic flow and request metadata.
pub(super) trait HarnessDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
    ) -> Option<HarnessDetection>;
}

/// Stateless detector registry evaluated against the current policy snapshot.
pub struct HarnessRegistry;

impl HarnessRegistry {
    pub fn detect_http(
        exchange: &HttpExchange,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        Self::detect(
            &exchange.flow,
            exchange.request.headers(),
            exchange.request.uri().path(),
            config,
        )
    }

    pub fn detect_websocket(
        message: &WebSocketMessage,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        Self::detect(
            &message.flow,
            message.upgrade_request.headers(),
            message.upgrade_request.uri().path(),
            config,
        )
    }

    fn detect(
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        let detectors: [&dyn HarnessDetector; 6] = [
            &codex::CodexDetector,
            &claude_desktop::ClaudeDesktopDetector,
            &claude_code::ClaudeCodeDetector,
            &deepseek_harness::DeepSeekHarnessDetector,
            &openclaw::OpenClawDetector,
            &hermes::HermesDetector,
        ];
        let mut detections = detectors
            .into_iter()
            .filter_map(|detector| detector.detect(flow, headers, path))
            .collect::<Vec<_>>();

        // These clients can send Codex/Claude compatibility fingerprints.
        // Apply their explicit identity before policy filtering so disabling
        // one cannot relabel its traffic as the impersonated client.
        if detections
            .iter()
            .any(|detection| matches!(detection.harness_id.as_str(), "openclaw" | "hermes"))
        {
            detections.retain(|detection| {
                !matches!(detection.harness_id.as_str(), "codex" | "claude-code")
            });
        }
        detections.retain(|detection| config.enabled_for_harness(detection.harness_id.as_str()));

        for (harness_id, harness) in &config.harnesses {
            if harness_id.is_reserved() || !harness.enabled.unwrap_or(true) {
                continue;
            }
            if let Some(evidence) = harness
                .matchers
                .iter()
                .find_map(|matcher| HarnessMatcher::new(matcher).matches(flow))
            {
                detections.push(HarnessDetection {
                    harness_id: harness_id.clone(),
                    evidence,
                    version: None,
                    working_directory: flow.source_working_directory().map(str::to_owned),
                });
            }
        }

        if detections.len() != 1 {
            if detections.len() > 1 {
                let harnesses = detections
                    .iter()
                    .map(|detection| detection.harness_id.as_str())
                    .collect::<Vec<_>>();
                tracing::warn!(?harnesses, "ambiguous Harness detection; skipping event");
            }
            return None;
        }
        detections.pop()
    }
}

impl HarnessRegistry {
    /// Newly integrated clients require an explicit client-owned session.
    #[must_use]
    pub fn requires_session(harness_id: &HarnessId) -> bool {
        matches!(harness_id.as_str(), "openclaw" | "hermes")
    }

    /// Reads what the detected Agent declares about a request. Agents without
    /// built-in declarations declare nothing.
    #[must_use]
    pub fn declare(harness_id: &HarnessId, source: &DeclarationSource<'_>) -> AgentDeclaration {
        match harness_id.as_str() {
            id if id == BuiltInHarness::Codex.id() => codex::declare(source),
            id if id == BuiltInHarness::ClaudeCode.id() => claude_code::declare(source),
            id if id == BuiltInHarness::OpenClaw.id() => openclaw::declare(source),
            id if id == BuiltInHarness::Hermes.id() => hermes::declare(source),
            _ => AgentDeclaration::default(),
        }
    }
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

// Match only the executable/name basename, never a parent directory or a
// generic interpreter. Process identity comes from ingress, not HTTP headers.
fn process_evidence(flow: &FlowContext, names: &[&str]) -> Option<HarnessEvidence> {
    let source = flow.source_process.as_ref()?;
    source
        .name
        .as_deref()
        .into_iter()
        .chain(source.executable_path.as_deref())
        .find(|value| {
            let basename = value.trim().rsplit(['/', '\\']).next().unwrap_or_default();
            let normalized = basename.to_ascii_lowercase();
            let normalized = normalized.strip_suffix(".exe").unwrap_or(&normalized);
            names.contains(&normalized)
        })
        .map(|value| HarnessEvidence::Process(value.to_owned()))
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
        CapturedBody, FlowContext, HttpExchange, OriginalDestination, TransparentProtocol,
        WebSocketDirection, WebSocketMessage,
    };
    use http::{HeaderMap, Request, Response};

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
            // OpenClaw's installed pi-ai transport identifies itself as pi.
            (
                vec![
                    ("user-agent", "pi (darwin; arm64)"),
                    ("originator", "pi"),
                    ("x-openclaw-session-id", "session-1"),
                ],
                Some("openclaw"),
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
                    ("x-openclaw-session-id", "session-1"),
                ],
                Some("openclaw"),
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
            let mut headers = HeaderMap::new();
            if let Some(value) = user_agent {
                headers.insert("user-agent", value.parse().unwrap());
            }
            let detected = HarnessRegistry::detect(&flow, &headers, "/responses", &config);
            assert_eq!(detected.is_some(), expected, "{user_agent:?}");
            if let Some(detected) = detected {
                assert_eq!(detected.harness_id.as_str(), "deepseek-harness");
                assert_eq!(detected.version.as_deref(), Some("0.2.0-rc.2"));
            }
        }

        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "deepseek-harness/0.2.0-rc.2".parse().unwrap());
        let disabled = serde_json::from_value::<HarnessUsageConfig>(serde_json::json!({
            "harnesses": {"deepseek-harness": {"enabled": false}}
        }))
        .unwrap();
        assert!(HarnessRegistry::detect(&flow, &headers, "/responses", &disabled).is_none());

        // Preserve the registry's rejection of conflicting Harness identities.
        headers.insert("x-codex-turn-metadata", "{}".parse().unwrap());
        assert!(HarnessRegistry::detect(&flow, &headers, "/responses", &config).is_none());
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
            HarnessRegistry::detect(
                &flow,
                &HeaderMap::new(),
                "/api/organizations/org-id/chat_conversations/conversation-id/completion",
                &HarnessUsageConfig::default(),
            )
            .is_none()
        );
    }
}
