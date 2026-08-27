//! Harness identity, detection evidence, custom matching, and detector registry.

pub mod detection;
mod id;
pub mod matcher;
pub mod registry;

pub use detection::{HarnessDetection, HarnessEvidence};
pub use id::{BuiltInHarness, HarnessId};
pub use registry::HarnessRegistry;
