//! Configured Harness identity matching over source process and application metadata.

use abyss_mitm::FlowContext;

use crate::config::HarnessMatcherConfig;

pub struct HarnessMatcher<'a> {
    config: &'a HarnessMatcherConfig,
}

impl<'a> HarnessMatcher<'a> {
    pub const fn new(config: &'a HarnessMatcherConfig) -> Self {
        Self { config }
    }

    /// Whether the flow satisfies every populated matcher field; a matcher
    /// with no populated field matches nothing.
    pub fn matches(&self, flow: &FlowContext) -> bool {
        let source = flow.source_process.as_ref();
        let process_names = &self.config.process_names;
        let application_ids = &self.config.application_ids;
        if process_names.is_empty() && application_ids.is_empty() {
            return false;
        }
        let process_matches = process_names.is_empty()
            || source
                .and_then(|source| source.name.as_deref())
                .is_some_and(|name| process_names.iter().any(|candidate| candidate == name));
        let application_matches = application_ids.is_empty()
            || source
                .and_then(|source| source.application_id.as_deref())
                .is_some_and(|id| application_ids.iter().any(|candidate| candidate == id));
        process_matches && application_matches
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use abyss_mitm::{FlowContext, OriginalDestination, SourceProcess, TransparentProtocol};

    use crate::config::HarnessMatcherConfig;

    use super::HarnessMatcher;

    #[test]
    fn populated_fields_use_and_semantics() {
        let flow = flow(Some("acme"), Some("com.acme.agent"));
        let matcher = HarnessMatcherConfig {
            process_names: vec!["acme".to_owned(), "acme-cli".to_owned()],
            application_ids: vec!["com.acme.agent".to_owned()],
        };

        assert!(HarnessMatcher::new(&matcher).matches(&flow));
    }

    #[test]
    fn missing_populated_source_field_does_not_match() {
        let flow = flow(Some("acme"), None);
        let matcher = HarnessMatcherConfig {
            process_names: vec!["acme".to_owned()],
            application_ids: vec!["com.acme.agent".to_owned()],
        };

        assert!(!HarnessMatcher::new(&matcher).matches(&flow));
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
