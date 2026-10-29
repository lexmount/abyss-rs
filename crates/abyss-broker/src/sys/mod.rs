//! Safe wrappers around native OS APIs used by the broker.

#[cfg(target_os = "windows")]
mod callout;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub mod winsock;

#[cfg(target_os = "windows")]
pub use callout::query_redirect_metadata;
#[cfg(target_os = "macos")]
pub use macos::{process_working_directory, sysctl_read};
