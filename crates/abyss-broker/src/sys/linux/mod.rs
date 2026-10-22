//! Read-only Linux procfs adapters for local connection and process attribution.
//! Missing permissions or vanished processes leave metadata unavailable.

mod process;
mod socket_owner;

pub use process::{process_arguments, process_executable, process_working_directory};
pub use socket_owner::connection_pid;
