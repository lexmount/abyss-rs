//! TLS decryption policy for transparent HTTPS flows.
//!
//! The policy decides whether a TLS connection should be MITM-decrypted after
//! the client `ClientHello` exposes SNI, but before Abyss generates a leaf
//! certificate or accepts client TLS.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::hook::SourceProcess;

/// Action selected by TLS decryption policy.
#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TlsDecryptionAction {
    /// Terminate client TLS and expose HTTP/WebSocket plaintext to hooks.
    Intercept,
    /// Keep the TLS session opaque and relay raw bytes to the original server.
    #[default]
    Passthrough,
}

/// Source- and destination-aware TLS decryption policy.
///
/// Rules are evaluated in JSON order. Selector dimensions inside one rule are
/// combined with logical AND, values inside one dimension use logical OR, and
/// an empty dimension is unconstrained. The first enabled matching rule selects
/// the action. If source attribution required by a rule is unavailable, that
/// rule does not match and evaluation continues. If no rule matches,
/// `default_action` is used.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDecryptionPolicy {
    /// Action used when no enabled rule matches.
    #[serde(default)]
    pub default_action: TlsDecryptionAction,
    /// Optional action used when the `ClientHello` does not carry SNI.
    ///
    /// When omitted, missing-SNI flows use `default_action`.
    #[serde(default)]
    pub missing_sni_action: Option<TlsDecryptionAction>,
    /// Ordered source- and destination-aware rules.
    #[serde(default)]
    pub rules: Vec<TlsDecryptionRule>,
}

/// TLS decryption policy that has passed all structural validation.
///
/// Keeping validation in this type separates fallible policy preparation from
/// the infallible atomic publication performed by [`MitmEngine`](super::MitmEngine).
pub struct ValidatedTlsDecryptionPolicy {
    policy: TlsDecryptionPolicy,
}

/// One ordered TLS decryption rule.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsDecryptionRule {
    /// Stable operator-facing rule identifier.
    pub id: String,
    /// Whether this rule participates in matching.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Action selected when the rule matches.
    pub action: TlsDecryptionAction,
    /// Exact source process names. Empty means any process name.
    ///
    /// A populated selector does not match when process attribution is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,
    /// Exact platform-normalized source application identities. Empty means any application.
    ///
    /// A populated selector does not match when application identity is absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ids: Vec<String>,
    /// Exact hosts or leading-wildcard suffixes such as `*.openai.com`.
    #[serde(default)]
    pub destination_hosts: Vec<String>,
}

/// Metadata available while selecting the TLS decryption action for one flow.
pub struct TlsDecryptionContext<'a> {
    destination_domain: Option<&'a str>,
    source_process: Option<&'a SourceProcess>,
}

/// Result of evaluating a TLS decryption policy.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TlsDecryptionDecision {
    /// Decrypt the TLS flow.
    Intercept {
        /// Identifier of the matched rule, when a rule selected the action.
        matched_rule_id: Option<String>,
    },
    /// Relay the TLS flow without decryption.
    Passthrough {
        /// Identifier of the matched rule, when a rule selected the action.
        matched_rule_id: Option<String>,
    },
}

/// Validation failure for TLS decryption configuration.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsDecryptionPolicyError {
    /// A rule id was empty after trimming.
    #[error("TLS decryption rule id must not be empty")]
    EmptyRuleId,
    /// A rule did not constrain any source or destination dimension.
    #[error(
        "TLS decryption rule `{rule_id}` requires destination_hosts, process_names, or application_ids"
    )]
    EmptySelectors {
        /// Rule id that failed validation.
        rule_id: String,
    },
    /// A process-name selector was empty after trimming.
    #[error("TLS decryption rule `{rule_id}` contains an empty process name")]
    EmptyProcessName {
        /// Rule id that failed validation.
        rule_id: String,
    },
    /// An application-id selector was empty after trimming.
    #[error("TLS decryption rule `{rule_id}` contains an empty application id")]
    EmptyApplicationId {
        /// Rule id that failed validation.
        rule_id: String,
    },
    /// A host pattern was malformed.
    #[error("TLS decryption rule `{rule_id}` contains invalid host pattern `{pattern}`: {reason}")]
    InvalidHostPattern {
        /// Rule id that owns the bad pattern.
        rule_id: String,
        /// Original pattern string.
        pattern: String,
        /// Human-readable validation reason.
        reason: &'static str,
    },
}

impl Default for TlsDecryptionPolicy {
    fn default() -> Self {
        Self {
            // A proxy must not decrypt unrelated HTTPS traffic unless an
            // operator explicitly opts that destination into inspection.
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: Some(TlsDecryptionAction::Passthrough),
            rules: Vec::new(),
        }
    }
}

impl<'a> TlsDecryptionContext<'a> {
    /// Creates the policy input for one TLS flow.
    #[must_use]
    pub const fn new(
        destination_domain: Option<&'a str>,
        source_process: Option<&'a SourceProcess>,
    ) -> Self {
        Self {
            destination_domain,
            source_process,
        }
    }
}

impl<'a> From<Option<&'a str>> for TlsDecryptionContext<'a> {
    fn from(destination_domain: Option<&'a str>) -> Self {
        Self::new(destination_domain, None)
    }
}

impl TlsDecryptionPolicy {
    /// Returns whether deciding for a TLS flow requires looking at `ClientHello` SNI.
    #[must_use]
    pub fn requires_sni_peek(&self) -> bool {
        self.missing_sni_action.is_some()
            || !self.rules.is_empty()
            || self.default_action == TlsDecryptionAction::Passthrough
    }

    /// Validates rule identifiers and selector values.
    ///
    /// # Errors
    ///
    /// Returns an error when a rule has an empty id, no selectors, empty source
    /// selectors, or malformed host patterns.
    pub fn validate(&self) -> Result<(), TlsDecryptionPolicyError> {
        for rule in &self.rules {
            let rule_id = rule.id.trim();
            if rule_id.is_empty() {
                return Err(TlsDecryptionPolicyError::EmptyRuleId);
            }
            if rule.process_names.is_empty()
                && rule.application_ids.is_empty()
                && rule.destination_hosts.is_empty()
            {
                return Err(TlsDecryptionPolicyError::EmptySelectors {
                    rule_id: rule.id.clone(),
                });
            }
            if rule.process_names.iter().any(|name| name.trim().is_empty()) {
                return Err(TlsDecryptionPolicyError::EmptyProcessName {
                    rule_id: rule.id.clone(),
                });
            }
            if rule
                .application_ids
                .iter()
                .any(|application_id| application_id.trim().is_empty())
            {
                return Err(TlsDecryptionPolicyError::EmptyApplicationId {
                    rule_id: rule.id.clone(),
                });
            }
            for pattern in &rule.destination_hosts {
                validate_host_pattern(pattern).map_err(|reason| {
                    TlsDecryptionPolicyError::InvalidHostPattern {
                        rule_id: rule.id.clone(),
                        pattern: pattern.clone(),
                        reason,
                    }
                })?;
            }
        }
        Ok(())
    }

    /// Evaluates this policy against destination and source-process metadata.
    ///
    /// Passing an optional destination domain directly remains supported for
    /// callers that do not have source-process metadata.
    #[must_use]
    pub fn decide<'a, C>(&self, context: C) -> TlsDecryptionDecision
    where
        C: Into<TlsDecryptionContext<'a>>,
    {
        let context = context.into();
        let destination_domain = context.destination_domain.and_then(normalize_host);

        for rule in &self.rules {
            if rule.enabled && rule.matches(destination_domain.as_deref(), context.source_process) {
                return decision_for_action(rule.action, Some(rule.id.clone()));
            }
        }

        let action = if destination_domain.is_none() {
            self.missing_sni_action.unwrap_or(self.default_action)
        } else {
            self.default_action
        };
        decision_for_action(action, None)
    }
}

impl ValidatedTlsDecryptionPolicy {
    /// Validates a policy and prepares it for atomic publication.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy contains invalid rule identifiers,
    /// selector values, or host patterns.
    pub fn new(policy: TlsDecryptionPolicy) -> Result<Self, TlsDecryptionPolicyError> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub(super) fn into_inner(self) -> TlsDecryptionPolicy {
        self.policy
    }
}

impl TlsDecryptionRule {
    fn matches(
        &self,
        destination_domain: Option<&str>,
        source_process: Option<&SourceProcess>,
    ) -> bool {
        selector_matches(
            &self.process_names,
            source_process.and_then(|source| source.name.as_deref()),
        ) && selector_matches(
            &self.application_ids,
            source_process.and_then(|source| source.application_id.as_deref()),
        ) && destination_selector_matches(&self.destination_hosts, destination_domain)
    }
}

impl TlsDecryptionDecision {
    /// Returns the selected action without rule metadata.
    #[must_use]
    pub const fn action(&self) -> TlsDecryptionAction {
        match self {
            Self::Intercept { .. } => TlsDecryptionAction::Intercept,
            Self::Passthrough { .. } => TlsDecryptionAction::Passthrough,
        }
    }

    /// Returns the matched rule id when a rule selected this decision.
    #[must_use]
    pub fn matched_rule_id(&self) -> Option<&str> {
        match self {
            Self::Intercept { matched_rule_id } | Self::Passthrough { matched_rule_id } => {
                matched_rule_id.as_deref()
            }
        }
    }
}

#[expect(
    clippy::missing_const_for_fn,
    reason = "The function moves optional String rule metadata into the decision."
)]
fn decision_for_action(
    action: TlsDecryptionAction,
    matched_rule_id: Option<String>,
) -> TlsDecryptionDecision {
    match action {
        TlsDecryptionAction::Intercept => TlsDecryptionDecision::Intercept { matched_rule_id },
        TlsDecryptionAction::Passthrough => TlsDecryptionDecision::Passthrough { matched_rule_id },
    }
}

const fn enabled_by_default() -> bool {
    true
}

fn validate_host_pattern(pattern: &str) -> Result<(), &'static str> {
    let normalized = normalize_host_pattern(pattern).ok_or("host pattern is empty")?;
    if normalized.contains('*') && !normalized.starts_with("*.") {
        return Err("wildcards are only supported as a leading `*.` suffix match");
    }
    if normalized == "*." {
        return Err("wildcard suffix is empty");
    }
    let labels = normalized
        .strip_prefix("*.")
        .unwrap_or(&normalized)
        .split('.');
    if labels.into_iter().any(str::is_empty) {
        return Err("host contains an empty label");
    }
    Ok(())
}

fn host_pattern_matches(pattern: &str, server_name: &str) -> bool {
    let Some(pattern) = normalize_host_pattern(pattern) else {
        return false;
    };
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return server_name.ends_with(suffix)
            && server_name.strip_suffix(suffix).is_some_and(|prefix| {
                prefix
                    .strip_suffix('.')
                    .is_some_and(|label| !label.is_empty() && !label.contains('.'))
            });
    }
    pattern == server_name
}

fn selector_matches(selectors: &[String], candidate: Option<&str>) -> bool {
    selectors.is_empty()
        || candidate.is_some_and(|candidate| {
            selectors
                .iter()
                .any(|value| selector_value_matches(value, candidate))
        })
}

#[cfg(target_os = "windows")]
const fn selector_value_matches(selector: &str, candidate: &str) -> bool {
    selector.eq_ignore_ascii_case(candidate)
}

#[cfg(not(target_os = "windows"))]
fn selector_value_matches(selector: &str, candidate: &str) -> bool {
    selector == candidate
}

fn destination_selector_matches(selectors: &[String], candidate: Option<&str>) -> bool {
    selectors.is_empty()
        || candidate.is_some_and(|candidate| {
            selectors
                .iter()
                .any(|pattern| host_pattern_matches(pattern, candidate))
        })
}

fn normalize_host_pattern(pattern: &str) -> Option<String> {
    normalize_host(pattern)
}

fn normalize_host(host: &str) -> Option<String> {
    let host = host
        .split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if host.is_empty() { None } else { Some(host) }
}

#[cfg(test)]
mod tests {
    use super::{
        TlsDecryptionAction, TlsDecryptionContext, TlsDecryptionDecision, TlsDecryptionPolicy,
        TlsDecryptionPolicyError, TlsDecryptionRule,
    };
    use crate::SourceProcess;

    #[test]
    fn default_policy_passes_unknown_hosts_and_missing_sni() {
        let policy = TlsDecryptionPolicy::default();

        assert!(policy.requires_sni_peek());
        assert_eq!(
            policy.decide(Some("example.test")),
            TlsDecryptionDecision::Passthrough {
                matched_rule_id: None
            }
        );
        assert_eq!(
            policy.decide(None).action(),
            TlsDecryptionAction::Passthrough
        );
    }

    #[test]
    fn rule_order_selects_first_matching_host() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: None,
            rules: vec![
                TlsDecryptionRule {
                    id: "decrypt-openai".to_owned(),
                    enabled: true,
                    action: TlsDecryptionAction::Intercept,
                    process_names: Vec::new(),
                    application_ids: Vec::new(),
                    destination_hosts: vec!["openai.com".to_owned(), "*.openai.com".to_owned()],
                },
                TlsDecryptionRule {
                    id: "pass-api".to_owned(),
                    enabled: true,
                    action: TlsDecryptionAction::Passthrough,
                    process_names: Vec::new(),
                    application_ids: Vec::new(),
                    destination_hosts: vec!["api.openai.com".to_owned()],
                },
            ],
        };

        assert_eq!(
            policy.decide(Some("api.openai.com")),
            TlsDecryptionDecision::Intercept {
                matched_rule_id: Some("decrypt-openai".to_owned())
            }
        );
    }

    #[test]
    fn wildcard_matches_subdomains_but_not_apex() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: None,
            rules: vec![TlsDecryptionRule {
                id: "decrypt-subdomains".to_owned(),
                enabled: true,
                action: TlsDecryptionAction::Intercept,
                process_names: Vec::new(),
                application_ids: Vec::new(),
                destination_hosts: vec!["*.example.test".to_owned()],
            }],
        };

        assert_eq!(
            policy.decide(Some("api.example.test")).action(),
            TlsDecryptionAction::Intercept
        );
        assert_eq!(
            policy.decide(Some("example.test")).action(),
            TlsDecryptionAction::Passthrough
        );
        assert_eq!(
            policy.decide(Some("deep.api.example.test")).action(),
            TlsDecryptionAction::Passthrough
        );
    }

    #[test]
    fn missing_sni_uses_configured_missing_sni_action() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Intercept,
            missing_sni_action: Some(TlsDecryptionAction::Passthrough),
            rules: Vec::new(),
        };

        assert_eq!(
            policy.decide(None).action(),
            TlsDecryptionAction::Passthrough
        );
    }

    #[test]
    fn populated_dimensions_are_anded_and_values_within_each_dimension_are_ored() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: Some(TlsDecryptionAction::Passthrough),
            rules: vec![TlsDecryptionRule {
                id: "decrypt-codex-openai".to_owned(),
                enabled: true,
                action: TlsDecryptionAction::Intercept,
                process_names: vec!["codex".to_owned(), "codex-cli".to_owned()],
                application_ids: vec![
                    "com.example.other".to_owned(),
                    "com.openai.codex".to_owned(),
                ],
                destination_hosts: vec!["openai.com".to_owned(), "*.openai.com".to_owned()],
            }],
        };
        let matching_process = source_process(Some("codex-cli"), Some("com.openai.codex"));

        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(
                    Some("api.openai.com"),
                    Some(&matching_process),
                ))
                .action(),
            TlsDecryptionAction::Intercept
        );

        let wrong_process = source_process(Some("claude"), Some("com.openai.codex"));
        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(
                    Some("api.openai.com"),
                    Some(&wrong_process),
                ))
                .action(),
            TlsDecryptionAction::Passthrough
        );
    }

    #[test]
    fn unavailable_source_attribution_falls_through_to_default_action() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: None,
            rules: vec![TlsDecryptionRule {
                id: "decrypt-codex".to_owned(),
                enabled: true,
                action: TlsDecryptionAction::Intercept,
                process_names: vec!["codex".to_owned()],
                application_ids: vec!["com.openai.codex".to_owned()],
                destination_hosts: Vec::new(),
            }],
        };
        let process_without_application_id = source_process(Some("codex"), None);

        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(
                    Some("api.openai.com"),
                    Some(&process_without_application_id),
                ))
                .action(),
            TlsDecryptionAction::Passthrough
        );
        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(Some("api.openai.com"), None,))
                .action(),
            TlsDecryptionAction::Passthrough
        );
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_source_selectors_are_ascii_case_insensitive() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: None,
            rules: vec![TlsDecryptionRule {
                id: "decrypt-codex".to_owned(),
                enabled: true,
                action: TlsDecryptionAction::Intercept,
                process_names: vec!["codex.exe".to_owned()],
                application_ids: vec![r"c:\program files\openai\codex.exe".to_owned()],
                destination_hosts: Vec::new(),
            }],
        };
        let process = source_process(
            Some("Codex.EXE"),
            Some(r"C:\Program Files\OpenAI\Codex.exe"),
        );

        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(None, Some(&process)))
                .action(),
            TlsDecryptionAction::Intercept
        );
    }

    #[test]
    fn empty_destination_dimension_matches_a_process_even_without_sni() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: Some(TlsDecryptionAction::Passthrough),
            rules: vec![TlsDecryptionRule {
                id: "decrypt-codex".to_owned(),
                enabled: true,
                action: TlsDecryptionAction::Intercept,
                process_names: vec!["codex".to_owned()],
                application_ids: Vec::new(),
                destination_hosts: Vec::new(),
            }],
        };
        let process = source_process(Some("codex"), None);

        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(None, Some(&process)))
                .action(),
            TlsDecryptionAction::Intercept
        );
    }

    #[test]
    fn validation_requires_at_least_one_selector_dimension() {
        let policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: None,
            rules: vec![TlsDecryptionRule {
                id: "unconstrained".to_owned(),
                enabled: true,
                action: TlsDecryptionAction::Intercept,
                process_names: Vec::new(),
                application_ids: Vec::new(),
                destination_hosts: Vec::new(),
            }],
        };

        assert!(matches!(
            policy.validate(),
            Err(TlsDecryptionPolicyError::EmptySelectors { .. })
        ));
    }

    #[test]
    fn validation_rejects_empty_source_selector_values() {
        let mut rule = process_rule(" ");
        let mut policy = TlsDecryptionPolicy {
            default_action: TlsDecryptionAction::Passthrough,
            missing_sni_action: None,
            rules: vec![rule.clone()],
        };
        assert!(matches!(
            policy.validate(),
            Err(TlsDecryptionPolicyError::EmptyProcessName { .. })
        ));

        rule.process_names.clear();
        rule.application_ids.push(String::new());
        policy.rules = vec![rule];
        assert!(matches!(
            policy.validate(),
            Err(TlsDecryptionPolicyError::EmptyApplicationId { .. })
        ));
    }

    #[test]
    fn destination_only_json_remains_api_compatible() {
        let json = serde_json::json!({
            "default_action": "passthrough",
            "rules": [{
                "id": "decrypt-openai",
                "action": "intercept",
                "destination_hosts": ["*.openai.com"]
            }]
        });

        let policy: TlsDecryptionPolicy =
            serde_json::from_value(json.clone()).expect("legacy policy should deserialize");
        policy.validate().expect("legacy policy should validate");
        assert!(policy.rules[0].process_names.is_empty());
        assert!(policy.rules[0].application_ids.is_empty());

        let serialized = serde_json::to_value(policy).expect("policy should serialize");
        assert_eq!(
            serialized["rules"][0]["destination_hosts"],
            json["rules"][0]["destination_hosts"]
        );
        assert!(serialized["rules"][0].get("process_names").is_none());
        assert!(serialized["rules"][0].get("application_ids").is_none());
    }

    fn process_rule(process_name: &str) -> TlsDecryptionRule {
        TlsDecryptionRule {
            id: "process-rule".to_owned(),
            enabled: true,
            action: TlsDecryptionAction::Intercept,
            process_names: vec![process_name.to_owned()],
            application_ids: Vec::new(),
            destination_hosts: Vec::new(),
        }
    }

    fn source_process(name: Option<&str>, application_id: Option<&str>) -> SourceProcess {
        SourceProcess::new(None, name.map(str::to_owned), None)
            .with_application_id(application_id.map(str::to_owned))
    }
}
