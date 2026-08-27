//! Exact source-process matching for configured third-party Harnesses.

use abyss_mitm::FlowContext;

use crate::config::HarnessMatcherConfig;

use super::HarnessEvidence;

pub struct HarnessMatcher<'a> {
    config: &'a HarnessMatcherConfig,
}

impl<'a> HarnessMatcher<'a> {
    pub const fn new(config: &'a HarnessMatcherConfig) -> Self {
        Self { config }
    }

    pub fn matches(&self, flow: &FlowContext) -> Option<Vec<HarnessEvidence>> {
        if self.config.process_names.is_empty() && self.config.application_ids.is_empty() {
            return None;
        }
        let source = flow.source_process.as_ref()?;
        let mut evidence = Vec::new();

        if !self.config.process_names.is_empty() {
            let process_name = source.name.as_deref()?;
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
            let application_id = source.application_id.as_deref()?;
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

        Some(evidence)
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

        assert_eq!(
            HarnessMatcher::new(&matcher).matches(&flow).unwrap().len(),
            2
        );
    }

    #[test]
    fn missing_populated_source_field_does_not_match() {
        let flow = flow(Some("acme"), None);
        let matcher = HarnessMatcherConfig {
            process_names: vec!["acme".to_owned()],
            application_ids: vec!["com.acme.agent".to_owned()],
        };

        assert!(HarnessMatcher::new(&matcher).matches(&flow).is_none());
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
