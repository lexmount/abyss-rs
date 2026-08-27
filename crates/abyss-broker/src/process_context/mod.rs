//! Platform-neutral process-context resolution and caching boundaries.
//!
//! Ingress adapters depend on the `ProcessContextResolver` trait. Conditional
//! compilation selects a native provider, while the shared cache keeps
//! per-process lookups out of the flow hot path.

#![cfg_attr(
    not(target_os = "macos"),
    expect(
        dead_code,
        reason = "process context is currently populated only by the macOS platform ingress"
    )
)]

mod cache;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod unavailable;

use std::{path::PathBuf, sync::Arc};

use cache::CachedProcessContextResolver;

/// Resolves best-effort metadata for the process that opened a network flow.
pub trait ProcessContextResolver: Send + Sync {
    /// Returns the source process working directory when the platform exposes it.
    fn working_directory(&self, pid: Option<u32>, pid_version: Option<u32>) -> Option<PathBuf>;
}

/// Shared process-context resolver used across accepted flow tasks.
pub type SharedProcessContextResolver = Arc<dyn ProcessContextResolver>;

/// Builds the cached resolver selected for the current target.
#[cfg(target_os = "macos")]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(CachedProcessContextResolver::new(
        macos::MacOsWorkingDirectoryProvider,
    ))
}

/// Builds a cached resolver that reports unavailable metadata on other targets.
#[cfg(not(target_os = "macos"))]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(CachedProcessContextResolver::new(
        unavailable::UnavailableWorkingDirectoryProvider,
    ))
}
