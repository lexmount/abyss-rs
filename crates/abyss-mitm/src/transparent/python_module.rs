//! Validated Python module names shared by process attribution and TLS policy.
//!
//! Names describe `python -m` entry points, not import resolution or code identity.

use serde::{Deserialize, Serialize};

/// A conservative, case-sensitive dotted ASCII Python module name.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(try_from = "String", into = "String")]
pub struct PythonModule(String);

impl PythonModule {
    /// Validates a module name without importing it or inspecting the filesystem.
    ///
    /// # Errors
    ///
    /// Rejects empty components, non-ASCII identifiers, paths and option strings.
    pub fn new(name: String) -> Result<Self, &'static str> {
        if name.len() > 255
            || !name.split('.').all(|component| {
                let mut bytes = component.bytes();
                bytes
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                    && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        {
            return Err("expected a dotted ASCII Python module name (at most 255 bytes)");
        }
        Ok(Self(name))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PythonModule {
    type Error = &'static str;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<PythonModule> for String {
    fn from(value: PythonModule) -> Self {
        value.0
    }
}
