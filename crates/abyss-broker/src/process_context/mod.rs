//! Platform-neutral process-context resolution and caching boundaries.
//!
//! Ingress adapters depend on the `ProcessContextResolver` trait. Conditional
//! compilation selects a native provider. Working directories may be cached;
//! entry-point queries always read the current process arguments.

#![cfg_attr(
    not(any(target_os = "macos", windows)),
    expect(
        dead_code,
        reason = "process context is populated by the macOS and Windows platform ingresses"
    )
)]

#[cfg(any(not(windows), test))]
mod cache;
mod entry_point;
#[cfg(target_os = "macos")]
mod macos;
mod process_arguments;
mod runtime;
#[cfg(not(any(target_os = "macos", windows)))]
mod unavailable;

use std::{path::PathBuf, sync::Arc};

#[cfg(not(windows))]
use cache::CachedProcessContextResolver;
use entry_point::EntryPointResolver;
use process_arguments::process_arguments_provider;
pub use runtime::ProcessEntry;
#[cfg(windows)]
pub use runtime::is_python_interpreter;

/// Resolves best-effort metadata for the process that opened a network flow.
pub trait ProcessContextResolver: Send + Sync {
    /// Attaches only an identified entry; native argv never leaves the resolver.
    fn populate_entry(&self, source: abyss_mitm::SourceProcess) -> abyss_mitm::SourceProcess {
        match self.entry_point(source.pid) {
            Some(ProcessEntry::Script(path)) => source.with_entry_point(Some(path)),
            Some(ProcessEntry::PythonModule(module)) => source.with_python_module(Some(module)),
            None => source,
        }
    }

    /// Returns the source process working directory when the platform exposes it.
    #[cfg_attr(
        all(windows, not(test)),
        expect(dead_code, reason = "Windows ingress only queries entry points.")
    )]
    fn working_directory(&self, pid: Option<u32>, pid_version: Option<u32>) -> Option<PathBuf>;

    /// Returns a normalized runtime entry point when it can be identified reliably.
    fn entry_point(&self, _pid: Option<u32>) -> Option<ProcessEntry> {
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
        macos::MacOsWorkingDirectoryProvider,
        EntryPointResolver::new(process_arguments_provider()),
    ))
}

/// Builds a resolver with unavailable working directories and native arguments where supported.
#[cfg(not(any(target_os = "macos", windows)))]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(CachedProcessContextResolver::new(
        unavailable::UnavailableWorkingDirectoryProvider,
        EntryPointResolver::new(process_arguments_provider()),
    ))
}

/// Builds the Windows resolver without allocating an unavailable cwd cache.
#[cfg(windows)]
#[must_use]
pub fn default_process_context_resolver() -> SharedProcessContextResolver {
    Arc::new(EntryPointResolver::new(process_arguments_provider()))
}

#[cfg(windows)]
impl ProcessContextResolver for EntryPointResolver {
    fn working_directory(&self, _pid: Option<u32>, _pid_version: Option<u32>) -> Option<PathBuf> {
        None
    }

    fn entry_point(&self, pid: Option<u32>) -> Option<ProcessEntry> {
        self.resolve(pid)
    }
}
