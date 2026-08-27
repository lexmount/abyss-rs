//! Harness-specific enablement, content overrides, and custom source matchers.

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, de::Error as _};

use crate::harness::HarnessId;

use super::HarnessUsageContentConfig;

/// Harness usage hook behavior configuration.
#[derive(Debug, Clone, Default, Serialize)]
pub struct HarnessUsageConfig {
    /// Default content policy for all configured Harnesses.
    #[serde(default)]
    pub content: HarnessUsageContentConfig,
    /// Built-in enablement overrides and custom Harness definitions.
    #[serde(default, alias = "agents")]
    pub harnesses: BTreeMap<HarnessId, HarnessConfig>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HarnessUsageConfigWire {
    #[serde(default)]
    content: HarnessUsageContentConfig,
    #[serde(default, alias = "agents")]
    harnesses: BTreeMap<HarnessId, HarnessConfig>,
}

/// Optional policy override and source matchers for one Harness.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessConfig {
    /// Whether this Harness should produce usage events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Content policy override for this Harness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<HarnessUsageContentConfig>,
    /// Source matchers used by a custom Harness.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matchers: Vec<HarnessMatcherConfig>,
}

/// One custom Harness source matcher.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessMatcherConfig {
    /// Accepted source process names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub process_names: Vec<String>,
    /// Accepted platform-neutral application identities.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub application_ids: Vec<String>,
}

impl HarnessUsageConfig {
    /// Returns whether usage events are enabled for one Harness.
    #[must_use]
    pub fn enabled_for_harness(&self, harness_id: &str) -> bool {
        self.harnesses
            .get(harness_id)
            .and_then(HarnessConfig::enabled)
            .unwrap_or(true)
    }

    /// Returns the effective independent content policy for one Harness.
    #[must_use]
    pub fn content_for_harness(&self, harness_id: &str) -> HarnessUsageContentConfig {
        self.harnesses
            .get(harness_id)
            .and_then(HarnessConfig::content)
            .unwrap_or(&self.content)
            .clone()
    }
}

impl<'de> Deserialize<'de> for HarnessUsageConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = HarnessUsageConfigWire::deserialize(deserializer)?;
        for (harness_id, harness) in &wire.harnesses {
            if harness_id.is_reserved() {
                if !harness.matchers.is_empty() {
                    return Err(D::Error::custom(format!(
                        "built-in Harness `{harness_id}` cannot define custom matchers"
                    )));
                }
                continue;
            }
            if harness.matchers.is_empty() {
                return Err(D::Error::custom(format!(
                    "custom Harness `{harness_id}` requires at least one matcher"
                )));
            }
            for matcher in &harness.matchers {
                if matcher.process_names.is_empty() && matcher.application_ids.is_empty() {
                    return Err(D::Error::custom(format!(
                        "custom Harness `{harness_id}` contains an empty matcher"
                    )));
                }
                if matcher
                    .process_names
                    .iter()
                    .chain(&matcher.application_ids)
                    .any(|value| value.trim().is_empty())
                {
                    return Err(D::Error::custom(format!(
                        "custom Harness `{harness_id}` contains an empty matcher value"
                    )));
                }
            }
        }
        Ok(Self {
            content: wire.content,
            harnesses: wire.harnesses,
        })
    }
}

impl HarnessConfig {
    const fn enabled(&self) -> Option<bool> {
        self.enabled
    }

    const fn content(&self) -> Option<&HarnessUsageContentConfig> {
        self.content.as_ref()
    }
}
