//! Platform-neutral process-context resolution and caching boundaries.
//!
//! Ingress adapters depend on the `ProcessContextResolver` trait. Conditional
//! compilation selects a native provider. Working directories are cached;
//! PID-based entry points are refreshed for each connection.

#![cfg_attr(
    not(any(target_os = "macos", target_os = "linux")),
    expect(
        dead_code,
        reason = "process context is currently populated only on macOS and Linux"
    )
)]

mod cache;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod entry_point;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod unavailable;

use std::{path::PathBuf, sync::Arc};

use cache::CachedProcessContextResolver;
#[cfg(target_os = "linux")]
pub use linux::local_source_process;

/// Resolves best-effort metadata for the process that opened a network flow.
pub trait ProcessContextResolver: Send + Sync {
    /// Returns the source process working directory when the platform exposes it.
    fn working_directory(&self, pid: Option<u32>, pid_version: Option<u32>) -> Option<PathBuf>;

    /// Returns a normalized runtime entry point when it can be identified reliably.
    fn entry_point(&self, _pid: Option<u32>) -> Option<String> {
        None
    }
}

/// Shared process-context resolver used across accepted flow tasks.
pub type SharedProcessContextResolver = Arc<dyn ProcessContextResolver>;

/// Builds the cached resolver selected for the current target.
#[cfg(target_os = "macos")]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(CachedProcessContextResolver::new(
        macos::MacOsProcessContextProvider,
    ))
}

/// Builds a cached resolver that reports unavailable metadata on other targets.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(CachedProcessContextResolver::new(
        unavailable::UnavailableProcessContextProvider,
    ))
}

/// Builds the native Linux resolver for local explicit-proxy connections.
#[cfg(target_os = "linux")]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(CachedProcessContextResolver::new(
        linux::LinuxProcessContextProvider,
    ))
}
