//! Runtime-specific command interpretation after the platform has supplied argv.
//!
//! Recognition and command parsing belong to each runtime. Only identified paths
//! are emitted; module names, inline code and arbitrary arguments are not paths.

mod node;
mod packaged_electron;
mod path;

use super::process_arguments::ProcessArguments;

pub(super) trait RuntimeEntryPointResolver: Send + Sync {
    fn recognizes(&self, executable: &str) -> bool;

    /// Returns the launch target, excluding runtime options and script arguments.
    fn parse_command<'a>(&self, arguments: &'a ProcessArguments) -> Option<&'a str>;

    /// Resolves a launch target to the path representation used by TLS rules.
    fn execution_path(&self, executable: &str, target: &str) -> Option<String>;
}

pub(super) fn runtime_resolvers() -> Vec<Box<dyn RuntimeEntryPointResolver>> {
    vec![
        Box::new(node::NodeEntryPoint),
        Box::new(packaged_electron::PackagedElectronEntryPoint),
    ]
}
