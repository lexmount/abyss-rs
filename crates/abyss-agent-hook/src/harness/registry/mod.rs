//! Built-in and configured Harness detection over generic request metadata.

mod claude_code;
mod claude_desktop;
mod codex;
mod deepseek;

use abyss_mitm::{FlowContext, HttpExchange, WebSocketMessage};
use http::HeaderMap;

use crate::config::HarnessUsageConfig;

use super::{HarnessDetection, matcher::HarnessMatcher, session::HarnessSessionResolver};

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
        let mut detection = Self::detect(
            &exchange.flow,
            exchange.request.headers(),
            exchange.request.uri().path(),
            config,
        )?;
        detection.session_id = HarnessSessionResolver::http(&detection.harness_id, exchange);
        Some(detection)
    }

    pub fn detect_websocket(
        message: &WebSocketMessage,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        let mut detection = Self::detect(
            &message.flow,
            message.upgrade_request.headers(),
            message.upgrade_request.uri().path(),
            config,
        )?;
        detection.session_id = HarnessSessionResolver::headers(
            &detection.harness_id,
            message.upgrade_request.headers(),
        );
        Some(detection)
    }

    fn detect(
        flow: &FlowContext,
        headers: &HeaderMap,
        path: &str,
        config: &HarnessUsageConfig,
    ) -> Option<HarnessDetection> {
        let detectors: [&dyn HarnessDetector; 4] = [
            &codex::CodexDetector,
            &claude_desktop::ClaudeDesktopDetector,
            &claude_code::ClaudeCodeDetector,
            &deepseek::DeepSeekHarnessDetector,
        ];
        let mut detections = detectors
            .into_iter()
            .filter_map(|detector| detector.detect(flow, headers, path))
            .filter(|detection| config.enabled_for_harness(detection.harness_id.as_str()))
            .collect::<Vec<_>>();

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
                    session_id: None,
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

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)?
        .to_str()
        .ok()
        .map(str::trim)
        .filter(|value| !value.is_empty())
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

    use abyss_mitm::{FlowContext, OriginalDestination, SourceProcess, TransparentProtocol};
    use http::HeaderMap;

    use crate::config::HarnessUsageConfig;

    use super::HarnessRegistry;

    #[test]
    fn deepseek_recognition_requires_its_user_agent_product_token() {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(SourceProcess::new(
                None,
                Some("deepseek-harness".to_owned()),
                None,
            )),
        );
        let mut headers = HeaderMap::new();
        headers.insert("host", "api.deepseek.com".parse().unwrap());
        headers.insert("originator", "deepseek-harness/0.2.0".parse().unwrap());
        for user_agent in [
            None,
            Some("deepseek-harness/"),
            Some("not-deepseek-harness/0.2.0"),
            Some("deepseek-harness-other/0.2.0"),
            Some("SDK/1.0 (+https://github.com/deepseek-ai/deepseek-harness)"),
        ] {
            if let Some(value) = user_agent {
                headers.insert("user-agent", value.parse().unwrap());
            }
            assert!(
                HarnessRegistry::detect(
                    &flow,
                    &headers,
                    "/deepseek-harness/v1/messages",
                    &HarnessUsageConfig::default(),
                )
                .is_none(),
                "unexpected match for {user_agent:?}"
            );
        }

        headers.insert("user-agent", "DeepSeek-Harness/0.2.0-rc.2".parse().unwrap());
        let detection = HarnessRegistry::detect(
            &flow,
            &headers,
            "/v1/messages",
            &HarnessUsageConfig::default(),
        )
        .expect("the User-Agent should identify DeepSeek Harness");
        assert_eq!(detection.harness_id.as_str(), "deepseek-harness");
        assert_eq!(detection.version.as_deref(), Some("0.2.0-rc.2"));
        assert_eq!(detection.evidence_names(), ["header:user-agent"]);
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
