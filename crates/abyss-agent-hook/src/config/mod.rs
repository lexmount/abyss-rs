//! Runtime policy snapshots and producer context for Harness audit hooks.

mod content;
mod harness;

use std::sync::Arc;

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

pub use content::HarnessUsageContentConfig;
pub use harness::{HarnessConfig, HarnessMatcherConfig, HarnessUsageConfig};

/// Dynamic configuration for all compiled-in MITM hooks.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HooksConfig {
    /// Harness usage audit hook configuration.
    #[serde(default, alias = "agent_usage")]
    pub harness_usage: HookConfig<HarnessUsageConfig>,
}

/// Common envelope for one compiled-in hook.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HookConfig<T> {
    /// Whether this hook should produce side effects.
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    /// Hook-owned behavior configuration.
    #[serde(default)]
    pub config: T,
}

/// Shared dynamic hooks configuration.
#[derive(Debug, Clone)]
pub struct HooksRuntimeConfig {
    inner: Arc<ArcSwap<HooksConfig>>,
}

/// Device identity attached to produced Agent events.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DeviceIdentity {
    /// Optional hostname for operator-friendly dashboards.
    pub hostname: Option<String>,
    /// Optional platform name such as `windows`, `macos`, or `linux`.
    pub platform: Option<String>,
    /// Optional operating-system version string.
    pub os_version: Option<String>,
}

/// Immutable producer context for Harness usage events.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HarnessUsageHookConfig {
    /// Device identity attached to every generated event.
    pub device: DeviceIdentity,
}

impl<T> Default for HookConfig<T>
where
    T: Default,
{
    fn default() -> Self {
        Self {
            enabled: true,
            config: T::default(),
        }
    }
}

impl HooksRuntimeConfig {
    /// Creates a dynamic hook config handle with the supplied initial snapshot.
    #[must_use]
    pub fn new(config: HooksConfig) -> Self {
        Self {
            inner: Arc::new(ArcSwap::from_pointee(config)),
        }
    }

    /// Creates a dynamic hook config handle with built-in defaults.
    #[must_use]
    pub fn default_enabled() -> Self {
        Self::new(HooksConfig::default())
    }

    /// Returns the current hooks configuration snapshot.
    #[must_use]
    pub fn snapshot(&self) -> Arc<HooksConfig> {
        self.inner.load_full()
    }

    /// Atomically replaces the hooks configuration for future hook invocations.
    #[must_use]
    pub fn update(&self, config: HooksConfig) -> HooksConfig {
        self.inner.store(Arc::new(config.clone()));
        config
    }
}

impl DeviceIdentity {
    /// Creates an empty device identity.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            hostname: None,
            platform: None,
            os_version: None,
        }
    }
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self::new()
    }
}

impl HarnessUsageHookConfig {
    /// Builds a producer configuration from explicit device identity.
    #[must_use]
    pub const fn new(device: DeviceIdentity) -> Self {
        Self { device }
    }

    /// Builds a producer configuration using local platform identity.
    #[must_use]
    pub fn from_platform() -> Self {
        Self::new(platform_device_identity())
    }
}

/// Returns the local platform identity used by Harness events.
#[must_use]
pub fn platform_device_identity() -> DeviceIdentity {
    let mut device = DeviceIdentity::new();
    device.hostname = system_hostname();
    device.platform = Some(std::env::consts::OS.to_owned());
    device
}

const fn enabled_by_default() -> bool {
    true
}

fn normalize_hostname(value: &str) -> Option<String> {
    let value = value.trim().trim_end_matches('.').to_owned();
    if value.is_empty() { None } else { Some(value) }
}

#[cfg(unix)]
fn system_hostname() -> Option<String> {
    nix::unistd::gethostname()
        .ok()
        .and_then(|value| value.into_string().ok())
        .and_then(|value| normalize_hostname(&value))
}

#[cfg(not(unix))]
fn system_hostname() -> Option<String> {
    std::env::var_os("COMPUTERNAME")
        .map(|value| value.to_string_lossy().into_owned())
        .and_then(|value| normalize_hostname(&value))
}

#[cfg(test)]
mod tests {
    use crate::harness::{BuiltInHarness, HarnessId};

    use super::{
        DeviceIdentity, HarnessConfig, HarnessMatcherConfig, HarnessUsageConfig,
        HarnessUsageContentConfig, HarnessUsageHookConfig, HookConfig, HooksConfig,
        HooksRuntimeConfig,
    };

    #[test]
    fn hook_config_contains_only_producer_identity() {
        let mut device = DeviceIdentity::new();
        device.hostname = Some("test-host".to_owned());
        let config = HarnessUsageHookConfig::new(device);

        assert_eq!(config.device.hostname.as_deref(), Some("test-host"));
    }

    #[test]
    fn hooks_config_defaults_to_enabled_plaintext_harness_usage() {
        let config = serde_json::from_str::<HooksConfig>("{}")
            .expect("empty hooks config should use defaults");

        assert!(config.harness_usage.enabled);
        let content = config
            .harness_usage
            .config
            .content_for_harness(BuiltInHarness::Codex.id());
        assert!(content.token_usage);
        assert!(content.conversation_text);
        assert!(content.tool_calls);
        assert!(content.images);

        let value = serde_json::to_value(config).expect("default hooks config should serialize");
        assert_eq!(
            value["harness_usage"]["config"]["content"],
            serde_json::json!({
                "token_usage": true,
                "conversation_text": true,
                "tool_calls": true,
                "images": true,
            })
        );
    }

    #[test]
    fn harness_usage_config_supports_custom_harnesses() {
        let config = serde_json::from_str::<HooksConfig>(
            r#"{
                "harness_usage": {
                    "config": {
                        "harnesses": {
                            "acme-agent": {
                                "enabled": true,
                                "matchers": [{
                                    "process_names": ["acme-agent"],
                                    "application_ids": ["com.acme.agent"]
                                }]
                            }
                        }
                    }
                }
            }"#,
        )
        .expect("custom Harness configuration should parse");

        let harness = config
            .harness_usage
            .config
            .harnesses
            .get("acme-agent")
            .expect("custom Harness should be retained");
        assert_eq!(harness.enabled, Some(true));
        assert_eq!(harness.matchers.len(), 1);
    }

    #[test]
    fn harness_usage_config_supports_per_harness_overrides() {
        let mut config = HarnessUsageConfig {
            content: HarnessUsageContentConfig {
                token_usage: true,
                conversation_text: false,
                tool_calls: false,
                images: false,
            },
            harnesses: std::collections::BTreeMap::new(),
        };
        config.harnesses.insert(
            HarnessId::from(BuiltInHarness::Codex),
            HarnessConfig {
                enabled: Some(false),
                content: Some(HarnessUsageContentConfig {
                    token_usage: false,
                    conversation_text: true,
                    tool_calls: true,
                    images: true,
                }),
                matchers: Vec::new(),
            },
        );

        assert!(!config.enabled_for_harness(BuiltInHarness::Codex.id()));
        assert!(
            !config
                .content_for_harness(BuiltInHarness::Codex.id())
                .token_usage
        );
        let claude = config.content_for_harness(BuiltInHarness::ClaudeCode.id());
        assert!(claude.token_usage);
        assert!(!claude.conversation_text);
    }

    #[test]
    fn legacy_agent_keys_migrate_during_deserialization() {
        let config = serde_json::from_str::<HooksConfig>(
            r#"{"agent_usage":{"config":{"agents":{"claude-cli":{"enabled":false}}}}}"#,
        )
        .expect("legacy Harness configuration should migrate");

        assert!(
            !config
                .harness_usage
                .config
                .enabled_for_harness(BuiltInHarness::ClaudeCode.id())
        );
        let value = serde_json::to_value(config).expect("migrated config should serialize");
        assert!(value.get("agent_usage").is_none());
        assert!(
            value["harness_usage"]["config"]["harnesses"]
                .as_object()
                .expect("Harness map should serialize as an object")
                .contains_key("claude-code")
        );
    }

    #[test]
    fn content_defaults_omitted_independent_controls() {
        let content =
            serde_json::from_str::<HarnessUsageContentConfig>(r#"{"conversation_text":false}"#)
                .expect("partial independent content policy should parse");

        assert!(content.token_usage);
        assert!(!content.conversation_text);
        assert!(content.tool_calls);
        assert!(content.images);
    }

    #[test]
    fn hooks_config_rejects_unknown_fields() {
        let unknown_hook =
            serde_json::from_str::<HooksConfig>(r#"{"future_hook":{"enabled":true}}"#);
        assert!(unknown_hook.is_err());

        let unknown_content = serde_json::from_str::<HooksConfig>(
            r#"{"harness_usage":{"config":{"content":{"future_content":true}}}}"#,
        );
        assert!(unknown_content.is_err());

        let unknown_matcher = serde_json::from_str::<HooksConfig>(
            r#"{"harness_usage":{"config":{"harnesses":{"acme":{"matchers":[{"future_matcher":["value"]}]}}}}}"#,
        );
        assert!(unknown_matcher.is_err());
    }

    #[test]
    fn hooks_runtime_config_updates_snapshots_without_mutating_old_handles() {
        let runtime = HooksRuntimeConfig::default_enabled();
        let before = runtime.snapshot();

        let updated = runtime.update(HooksConfig {
            harness_usage: HookConfig {
                enabled: false,
                config: HarnessUsageConfig::default(),
            },
        });

        assert!(!updated.harness_usage.enabled);
        assert!(before.harness_usage.enabled);
        assert!(!runtime.snapshot().harness_usage.enabled);
    }

    #[test]
    fn matcher_config_defaults_to_empty_selectors() {
        let matcher = serde_json::from_str::<HarnessMatcherConfig>("{}")
            .expect("empty matcher DTO should deserialize");
        assert!(matcher.process_names.is_empty());
        assert!(matcher.application_ids.is_empty());
    }

    #[test]
    fn custom_harness_requires_a_non_empty_matcher() {
        for input in [
            r#"{"harness_usage":{"config":{"harnesses":{"acme":{}}}}}"#,
            r#"{"harness_usage":{"config":{"harnesses":{"acme":{"matchers":[{}]}}}}}"#,
        ] {
            assert!(serde_json::from_str::<HooksConfig>(input).is_err());
        }
    }

    #[test]
    fn harness_id_uses_the_documented_wire_format() {
        for harness_id in ["", "Uppercase", "contains space"] {
            let input = format!(
                r#"{{"harness_usage":{{"config":{{"harnesses":{{"{harness_id}":{{"matchers":[{{"process_names":["acme"]}}]}}}}}}}}}}"#
            );
            assert!(serde_json::from_str::<HooksConfig>(&input).is_err());
        }
    }

    #[test]
    fn built_in_harness_cannot_be_redefined_with_custom_matchers() {
        let input = r#"{
            "harness_usage": {
                "config": {
                    "harnesses": {
                        "codex": {"matchers": [{"process_names": ["other"]}]}
                    }
                }
            }
        }"#;

        assert!(serde_json::from_str::<HooksConfig>(input).is_err());
    }
}
