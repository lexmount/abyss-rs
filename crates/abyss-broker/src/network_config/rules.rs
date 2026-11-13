//! Native source selectors for connection-wide egress; no HTTP harness inference.

use crate::error::BrokerError;
use abyss_mitm::{SourceProcess, outbound::UpstreamProxyConfig};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, path::Path};

/// Ordered source-specific route. Null upstream explicitly selects direct access.
/// Dimensions use AND; values within each dimension use OR. Missing attribution
/// never satisfies a populated dimension. Explicit ingress has no native source.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executable_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_entry_points: Vec<String>,
    pub upstream: Option<UpstreamProxyConfig>,
}

impl NetworkRule {
    pub(super) fn matches(&self, source: Option<&SourceProcess>) -> bool {
        matches_values(
            &self.process_names,
            source.and_then(|p| p.name.as_deref()),
            false,
        ) && matches_values(
            &self.application_ids,
            source.and_then(|p| p.application_id.as_deref()),
            false,
        ) && matches_values(
            &self.executable_paths,
            source.and_then(|p| p.executable_path.as_deref()),
            true,
        ) && matches_values(
            &self.process_entry_points,
            source.and_then(|p| p.entry_point.as_deref()),
            true,
        )
    }
}

pub(super) fn validate(rules: &[NetworkRule]) -> Result<(), BrokerError> {
    let mut ids = HashSet::new();
    for rule in rules {
        if rule.id.trim().is_empty() || !ids.insert(&rule.id) {
            return Err(BrokerError::invalid_config(
                "network rule IDs must be nonempty and unique",
            ));
        }
        let selectors = [
            &rule.process_names,
            &rule.application_ids,
            &rule.executable_paths,
            &rule.process_entry_points,
        ];
        if selectors.iter().all(|values| values.is_empty())
            || selectors
                .iter()
                .flat_map(|values| values.iter())
                .any(|s| s.trim().is_empty())
        {
            return Err(BrokerError::invalid_config(
                "network rules require nonempty native source selectors",
            ));
        }
        if rule
            .executable_paths
            .iter()
            .chain(&rule.process_entry_points)
            .any(|s| !Path::new(s).is_absolute())
        {
            return Err(BrokerError::invalid_config(
                "network source paths must be absolute",
            ));
        }
        if let Some(upstream) = &rule.upstream {
            upstream
                .validate()
                .map_err(|error| BrokerError::invalid_config(error.to_string()))?;
        }
    }
    Ok(())
}

fn matches_values(values: &[String], candidate: Option<&str>, path: bool) -> bool {
    values.is_empty()
        || candidate.is_some_and(|candidate| {
            values.iter().any(|value| {
                if path {
                    Path::new(value) == Path::new(candidate)
                } else if cfg!(target_os = "windows") {
                    value.eq_ignore_ascii_case(candidate)
                } else {
                    value == candidate
                }
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_config::{NetworkConfig, NetworkRuntime};
    use serde_json::json;

    #[test]
    fn ordered_source_routes_keep_unknown_sources_and_explicit_direct_distinct() {
        let config: NetworkConfig = serde_json::from_value(json!({
            "upstream":{"protocol":"http_connect","endpoint":"http://localhost:3100"},
            "rules":[
                {"id":"local","process_names":["codex"],"application_ids":["local"],"upstream":null},
                {"id":"codex","process_names":["codex","codex.exe"],"upstream":{"protocol":"http_connect","endpoint":"http://localhost:3200"}}
            ]
        })).unwrap();
        let runtime = NetworkRuntime::new(None, Some(config)).unwrap();
        let snapshot = runtime.snapshot();
        let codex = SourceProcess::new(None, Some("codex".to_owned()), None);
        assert_eq!(
            snapshot.for_source(Some(&codex)).unwrap().endpoint().port(),
            3200
        );
        assert_eq!(snapshot.for_source(None).unwrap().endpoint().port(), 3100);
        assert!(
            snapshot
                .for_source(Some(&codex.with_application_id(Some("local".to_owned()))))
                .is_none()
        );
        runtime.publish(NetworkRuntime::validate(NetworkConfig::default()).unwrap());
        assert!(runtime.snapshot().for_source(None).is_none());
        assert_eq!(snapshot.for_source(None).unwrap().endpoint().port(), 3100);
    }

    #[test]
    fn validates_all_rule_routes_before_publication() {
        for rules in [
            json!([{"id":"empty","upstream":null}]),
            json!([{"id":"bad","process_names":[" "],"upstream":null}]),
            json!([{"id":"bad","executable_paths":["relative"],"upstream":null}]),
            json!([{"id":"same","process_names":["a"],"upstream":null},{"id":"same","process_names":["b"],"upstream":null}]),
            json!([{"id":"proxy","process_names":["a"],"upstream":{"protocol":"http_connect","endpoint":"http://user:secret@localhost:1"}}]),
        ] {
            let config = serde_json::from_value(json!({"upstream":null,"rules":rules})).unwrap();
            assert!(NetworkRuntime::validate(config).is_err());
        }
    }
}
