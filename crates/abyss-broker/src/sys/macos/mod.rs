//! Safe macOS system API adapters used by broker business logic.

mod process;
mod process_arguments;

pub use process::process_working_directory;
pub(super) use process_arguments::MacOsProcessArgumentsProvider;
