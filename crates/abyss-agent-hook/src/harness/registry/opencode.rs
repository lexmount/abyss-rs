//! `OpenCode` identity and native request declarations, independent of its provider.
//! Shared gateway session headers alone do not identify the calling Harness.

use abyss_mitm::FlowContext;
use http::HeaderMap;

use crate::harness::{
    AgentDeclaration, BuiltInHarness, DeclarationSource, HarnessDetection, HarnessEvidence,
};

use super::{HarnessDetector, header};

pub(super) struct OpenCodeDetector;

impl HarnessDetector for OpenCodeDetector {
    fn detect(
        &self,
        flow: &FlowContext,
        headers: &HeaderMap,
        _path: &str,
    ) -> Option<HarnessDetection> {
        let version = Self::version(header(headers, "user-agent")?)?;
        Some(HarnessDetection {
            harness_id: BuiltInHarness::OpenCode.into(),
            evidence: vec![HarnessEvidence::Header("user-agent")],
            version: Some(version.to_owned()),
            working_directory: flow.source_working_directory().map(str::to_owned),
        })
    }
}

impl OpenCodeDetector {
    fn version(user_agent: &str) -> Option<&str> {
        let product = user_agent.split_whitespace().next()?;
        let value = product.strip_prefix("opencode/")?;
        if value.is_empty() {
            return None;
        }
        // Earlier clients sent opencode/<version>; current clients include the
        // release channel and client: opencode/<channel>/<version>/<client>.
        let Some((channel, tail)) = value.split_once('/') else {
            return Some(value);
        };
        let (version, client) = tail.split_once('/')?;
        (!channel.is_empty() && !version.is_empty() && !client.is_empty() && !client.contains('/'))
            .then_some(version)
    }
}

pub(super) fn declare(source: &DeclarationSource<'_>) -> AgentDeclaration {
    AgentDeclaration {
        // OpenCode sends the user message ID on its own gateway requests. Other
        // providers may omit it; session IDs and provider request IDs are not turns.
        turn_id: source
            .headers
            .and_then(|headers| header(headers, "x-opencode-request"))
            .map(str::to_owned),
        ..AgentDeclaration::default()
    }
}

#[cfg(test)]
mod tests {
    use super::OpenCodeDetector;

    #[test]
    fn version_comes_from_the_native_user_agent_not_the_release_channel() {
        for (user_agent, expected) in [
            ("opencode/latest/1.19.4/cli", Some("1.19.4")),
            ("opencode/dev/0.0.0-dev/desktop", Some("0.0.0-dev")),
            ("opencode/1.1.50", Some("1.1.50")),
            ("opencode/1.1.50 ai-sdk/5.0", Some("1.1.50")),
            ("other-opencode/1.19.4", None),
            ("ai-sdk/5.0 opencode/1.19.4", None),
            ("opencode/", None),
            ("opencode/latest/1.19.4", None),
            ("opencode//1.19.4/cli", None),
            ("opencode/latest//cli", None),
            ("opencode/latest/1.19.4/", None),
            ("opencode/latest/1.19.4/cli/other", None),
        ] {
            assert_eq!(
                OpenCodeDetector::version(user_agent),
                expected,
                "{user_agent}"
            );
        }
    }
}
