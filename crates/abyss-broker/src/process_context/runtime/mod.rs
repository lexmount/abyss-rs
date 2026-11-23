//! Runtime-specific interpretation of startup argv, without retaining application arguments.

mod node;
mod path;
mod python;

use super::process_arguments::ProcessArguments;
use abyss_mitm::PythonModule;

/// An execution entry is either an absolute script or a validated Python module.
#[derive(Debug, PartialEq)]
pub enum ProcessEntry {
    Script(String),
    PythonModule(PythonModule),
}

pub(super) trait RuntimeEntryPointResolver: Send + Sync {
    fn recognizes(&self, executable: &str) -> bool;
    fn resolve_entry(&self, arguments: &ProcessArguments) -> Option<ProcessEntry>;
}

pub(super) fn runtime_resolvers() -> Vec<Box<dyn RuntimeEntryPointResolver>> {
    vec![
        Box::new(node::NodeEntryPoint),
        Box::new(python::PythonEntryPoint),
    ]
}
