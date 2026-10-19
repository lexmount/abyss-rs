//! Configured Harness identity matching over source metadata and request headers.

use abyss_mitm::FlowContext;
use http::{HeaderMap, header::USER_AGENT};

use crate::config::HarnessMatcherConfig;

use super::HarnessEvidence;

pub struct HarnessMatcher<'a> {
    config: &'a HarnessMatcherConfig,
}

impl<'a> HarnessMatcher<'a> {
    pub const fn new(config: &'a HarnessMatcherConfig) -> Self {
        Self { config }
    }

    pub fn matches(&self, flow: &FlowContext, headers: &HeaderMap) -> Option<Vec<HarnessEvidence>> {
        let mut evidence = Vec::new();

        if !self.config.process_names.is_empty() {
            let process_name = flow.source_process.as_ref()?.name.as_deref()?;
            let matched = self
                .config
                .process_names
                .iter()
                .any(|candidate| candidate == process_name);
            if !matched {
                return None;
            }
            evidence.push(HarnessEvidence::Process(process_name.to_owned()));
        }

        if !self.config.application_ids.is_empty() {
            let application_id = flow.source_process.as_ref()?.application_id.as_deref()?;
            let matched = self
                .config
                .application_ids
                .iter()
                .any(|candidate| candidate == application_id);
            if !matched {
                return None;
            }
            evidence.push(HarnessEvidence::ApplicationId(application_id.to_owned()));
        }

        if !self.config.user_agent_prefixes.is_empty() {
            let user_agent = headers.get(USER_AGENT)?.to_str().ok()?;
            let matched = self
                .config
                .user_agent_prefixes
                .iter()
                .any(|prefix| !prefix.trim().is_empty() && user_agent.starts_with(prefix));
            if !matched {
                return None;
            }
            evidence.push(HarnessEvidence::Header("user-agent"));
        }

        (!evidence.is_empty()).then_some(evidence)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{FlowContext, OriginalDestination, SourceProcess, TransparentProtocol};
    use http::HeaderMap;

    use crate::config::HarnessMatcherConfig;

    use super::HarnessMatcher;

    #[test]
    fn populated_fields_use_and_semantics() {
        let flow = flow(Some("acme"), Some("com.acme.agent"));
        let matcher = HarnessMatcherConfig {
            process_names: vec!["acme".to_owned(), "acme-cli".to_owned()],
            application_ids: vec!["com.acme.agent".to_owned()],
            ..HarnessMatcherConfig::default()
        };

        assert_eq!(
            HarnessMatcher::new(&matcher)
                .matches(&flow, &HeaderMap::new())
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn missing_populated_source_field_does_not_match() {
        let flow = flow(Some("acme"), None);
        let matcher = HarnessMatcherConfig {
            process_names: vec!["acme".to_owned()],
            application_ids: vec!["com.acme.agent".to_owned()],
            ..HarnessMatcherConfig::default()
        };

        assert!(
            HarnessMatcher::new(&matcher)
                .matches(&flow, &HeaderMap::new())
                .is_none()
        );
    }

    #[test]
    fn user_agent_matching_requires_no_source_process_and_uses_literal_prefixes() {
        let mut flow = flow(None, None);
        flow.source_process = None;
        let matcher = HarnessMatcherConfig {
            user_agent_prefixes: vec!["other/".to_owned(), "acme-agent/".to_owned()],
            ..HarnessMatcherConfig::default()
        };
        for (user_agent, expected) in [
            (Some("acme-agent/1.2.3 (+https://example.com)"), true),
            (Some("other/2"), true),
            (Some("unrelated acme-agent/1.2.3"), false),
            (Some("acme-agent-else/1.2.3"), false),
            (Some("ACME-AGENT/1.2.3"), false),
            (None, false),
        ] {
            let mut headers = HeaderMap::new();
            if let Some(value) = user_agent {
                headers.insert("user-agent", value.parse().unwrap());
            }
            assert_eq!(
                HarnessMatcher::new(&matcher)
                    .matches(&flow, &headers)
                    .is_some(),
                expected,
                "{user_agent:?}"
            );
        }
    }

    #[test]
    fn user_agent_does_not_bypass_configured_source_constraints() {
        let matcher = HarnessMatcherConfig {
            process_names: vec!["acme".to_owned()],
            user_agent_prefixes: vec!["acme-agent/".to_owned()],
            ..HarnessMatcherConfig::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", "acme-agent/1".parse().unwrap());
        let mut flow = flow(Some("acme"), None);
        assert_eq!(
            HarnessMatcher::new(&matcher)
                .matches(&flow, &headers)
                .unwrap()
                .len(),
            2
        );
        assert!(
            HarnessMatcher::new(&matcher)
                .matches(&flow, &HeaderMap::new())
                .is_none()
        );
        flow.source_process = None;
        assert!(
            HarnessMatcher::new(&matcher)
                .matches(&flow, &headers)
                .is_none()
        );
    }

    fn flow(name: Option<&str>, application_id: Option<&str>) -> FlowContext {
        FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            TransparentProtocol::PlainHttp,
            Some(
                SourceProcess::new(None, name.map(str::to_owned), None)
                    .with_application_id(application_id.map(str::to_owned)),
            ),
        )
    }
}
