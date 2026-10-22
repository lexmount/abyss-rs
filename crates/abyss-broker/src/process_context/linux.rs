//! Linux process context and best-effort local explicit-proxy attribution.
//! Procfs scans run off the async workers with bounded concurrency.

use std::{net::SocketAddr, path::PathBuf, sync::OnceLock};

use abyss_mitm::SourceProcess;
use tokio::sync::Semaphore;

use super::{
    SharedProcessContextResolver, cache::ProcessContextProvider, default_process_context_resolver,
    entry_point::RuntimeEntryPoint,
};

pub(super) struct LinuxProcessContextProvider;

impl ProcessContextProvider for LinuxProcessContextProvider {
    fn lookup(&self, pid: u32) -> Option<PathBuf> {
        crate::sys::linux::process_working_directory(pid).ok()
    }

    fn entry_point(&self, pid: u32) -> Option<String> {
        let arguments = crate::sys::linux::process_arguments(pid).ok()?;
        RuntimeEntryPoint::resolve(
            &arguments.executable,
            &arguments
                .argv
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        )
    }
}

pub async fn local_source_process(peer: SocketAddr, local: SocketAddr) -> Option<SourceProcess> {
    static LOOKUPS: Semaphore = Semaphore::const_new(2);
    static RESOLVER: OnceLock<SharedProcessContextResolver> = OnceLock::new();
    let permit = LOOKUPS.acquire().await.ok()?;
    let resolver = RESOLVER
        .get_or_init(default_process_context_resolver)
        .clone();
    tokio::task::spawn_blocking(move || {
        // Keep the permit in the blocking task even if the caller is cancelled.
        let _permit = permit;
        let pid = crate::sys::linux::connection_pid(peer, local)?;
        let executable = crate::sys::linux::process_executable(pid).ok()?;
        let name = executable.file_name()?.to_str()?.to_owned();
        Some(
            SourceProcess::new(Some(pid), Some(name), Some(executable.to_str()?.to_owned()))
                .with_entry_point(resolver.entry_point(Some(pid)))
                .with_working_directory(
                    resolver
                        .working_directory(Some(pid), None)
                        .and_then(|path| path.to_str().map(str::to_owned)),
                ),
        )
    })
    .await
    .ok()
    .flatten()
}
