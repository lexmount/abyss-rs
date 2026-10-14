//! Harness identity, detection evidence, custom matching, and session metadata.

pub mod detection;
mod id;
pub mod matcher;
pub mod registry;
mod session;

pub use detection::{HarnessDetection, HarnessEvidence};
pub use id::{BuiltInHarness, HarnessId};
pub use registry::HarnessRegistry;
