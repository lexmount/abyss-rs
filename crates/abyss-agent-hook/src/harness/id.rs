//! Stable built-in and custom Harness identifiers.

use std::{borrow::Borrow, fmt};

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};

/// Built-in Harness implementations compiled into the broker.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum BuiltInHarness {
    /// OpenAI Codex CLI or app traffic.
    Codex,
    /// Anthropic Claude Code traffic.
    ClaudeCode,
    /// Anthropic Claude Desktop traffic.
    ClaudeDesktop,
}

impl BuiltInHarness {
    /// Returns the stable configuration and event identity.
    #[must_use]
    pub const fn id(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::ClaudeDesktop => "claude-desktop",
        }
    }
}

/// Stable built-in or custom Harness identity.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct HarnessId(String);

impl HarnessId {
    /// Returns the identifier as carried by configuration and Agent events.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns whether this identifier is reserved for a built-in detector.
    #[must_use]
    pub(crate) fn is_reserved(&self) -> bool {
        matches!(
            self.as_str(),
            "codex" | "claude-code" | "claude-desktop" | "openclaw"
        )
    }
}

impl From<BuiltInHarness> for HarnessId {
    fn from(value: BuiltInHarness) -> Self {
        Self(value.id().to_owned())
    }
}

impl Borrow<str> for HarnessId {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for HarnessId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for HarnessId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HarnessId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let value = if value == "claude-cli" {
            BuiltInHarness::ClaudeCode.id().to_owned()
        } else {
            value
        };
        if value.is_empty()
            || value.len() > 64
            || !value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
        {
            return Err(D::Error::custom(
                "Harness id must contain 1-64 lowercase ASCII letters, digits, '.', '_', or '-'",
            ));
        }
        Ok(Self(value))
    }
}
