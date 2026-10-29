//! Small platform adapters used by the broker.

#[cfg(target_os = "windows")]
mod callout;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod redirect_records;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
mod winsock;

#[cfg(target_os = "windows")]
pub use redirect_records::RedirectRecords;

#[cfg(target_os = "windows")]
pub use callout::query_redirect_metadata;
#[cfg(target_os = "macos")]
pub use macos::{process_working_directory, sysctl_read};
