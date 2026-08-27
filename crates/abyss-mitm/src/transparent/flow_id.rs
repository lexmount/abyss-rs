//! Stable identity for one accepted network flow.
//!
//! Platform adapters and native listeners use this identifier to preserve the
//! identity of a physical connection across protocol detection, TLS handling,
//! HTTP decoding, and product hooks. It deliberately carries no
//! platform-specific metadata.

use std::fmt;

use uuid::Uuid;

/// Process-independent identity of one accepted network flow.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct FlowId(Uuid);

impl FlowId {
    /// Generates an identity for an ingress that does not supply one.
    #[must_use]
    pub fn generate() -> Self {
        Self(Uuid::new_v4())
    }
}

impl From<Uuid> for FlowId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl fmt::Display for FlowId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

#[cfg(test)]
mod tests {
    use super::FlowId;

    #[test]
    fn generated_flow_ids_are_distinct() {
        assert_ne!(FlowId::generate(), FlowId::generate());
    }
}
