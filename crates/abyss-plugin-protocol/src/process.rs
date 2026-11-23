//! Runtime entry metadata shared by ingress, TLS configuration and plugin requests.
//!
//! Entries describe launch targets; they do not resolve imports or authenticate code.

use serde::{Deserialize, Serialize};

/// Runtime whose module execution syntax gives an entry name its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ModuleRuntime {
    /// Python's `-m` execution mode.
    Python,
}

impl ModuleRuntime {
    /// Checks the supported runtime's module syntax without resolving imports.
    #[must_use]
    pub fn accepts_module_name(self, name: &str) -> bool {
        match self {
            Self::Python => {
                name.len() <= 255
                    && name.split('.').all(|component| {
                        let mut bytes = component.bytes();
                        bytes
                            .next()
                            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
                    })
            }
        }
    }
}

/// One execution entry, used unchanged in source metadata and policy selectors.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ProcessEntry {
    /// Absolute entry script; platform-native path validation belongs to the broker.
    Script { path: String },
    /// A runtime-qualified module entry, independent of installation paths.
    Module {
        runtime: ModuleRuntime,
        name: String,
    },
}

impl ProcessEntry {
    /// Wraps an entry path identified by a runtime parser.
    #[must_use]
    pub const fn script(path: String) -> Self {
        Self::Script { path }
    }

    /// Constructs a module entry after checking its runtime-specific syntax.
    ///
    /// # Errors
    /// Returns an error when the name is not valid for the selected runtime.
    pub fn module(runtime: ModuleRuntime, name: String) -> Result<Self, &'static str> {
        if !runtime.accepts_module_name(&name) {
            return Err("invalid module name for the selected runtime");
        }
        Ok(Self::Module { runtime, name })
    }
}
