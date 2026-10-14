//! Harness identity, detection evidence, custom matching, detector registry,
//! and the declarations each built-in Agent makes about its requests.

pub mod declaration;
pub mod detection;
mod id;
pub mod matcher;
pub mod registry;

pub use declaration::{AgentDeclaration, DeclarationSource};
pub use detection::{HarnessDetection, HarnessEvidence};
pub use id::{BuiltInHarness, HarnessId};
pub use registry::HarnessRegistry;
