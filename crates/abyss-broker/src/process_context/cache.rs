//! Shared process-identity cache for platform process-context providers.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use super::ProcessContextResolver;

// A flow burst for one session normally completes well within this window. The
// PID version prevents PID reuse from sharing an entry, while expiry gives a
// long-lived process that calls chdir a chance to refresh its cwd.
const CACHE_TTL: Duration = Duration::from_mins(1);

#[derive(Eq, Hash, PartialEq)]
struct ProcessIdentity {
    pid: u32,
    pid_version: Option<u32>,
}

struct CacheEntry {
    working_directory: OnceLock<Option<PathBuf>>,
    entry_point: OnceLock<Option<String>>,
    expires_at: Instant,
}

pub(super) trait ProcessContextProvider: Send + Sync {
    fn lookup(&self, pid: u32) -> Option<PathBuf>;

    fn entry_point(&self, _pid: u32, _pid_version: Option<u32>) -> Option<String> {
        None
    }
}

pub(super) struct CachedProcessContextResolver<P> {
    provider: P,
    entries: Mutex<HashMap<ProcessIdentity, Arc<CacheEntry>>>,
}

impl<P> CachedProcessContextResolver<P>
where
    P: ProcessContextProvider,
{
    pub(super) fn new(provider: P) -> Self {
        Self {
            provider,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn entry(&self, identity: ProcessIdentity) -> Arc<CacheEntry> {
        let now = Instant::now();
        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.get(&identity)
                && entry.expires_at > now
            {
                Arc::clone(entry)
            } else {
                entries.retain(|_, entry| entry.expires_at > now);
                let expires_at = now.checked_add(CACHE_TTL).unwrap_or(now);
                let entry = Arc::new(CacheEntry {
                    working_directory: OnceLock::new(),
                    entry_point: OnceLock::new(),
                    expires_at,
                });
                entries.insert(identity, Arc::clone(&entry));
                entry
            }
        }
    }
}

impl<P> ProcessContextResolver for CachedProcessContextResolver<P>
where
    P: ProcessContextProvider,
{
    fn working_directory(&self, pid: Option<u32>, pid_version: Option<u32>) -> Option<PathBuf> {
        let pid = pid?;
        self.entry(ProcessIdentity { pid, pid_version })
            .working_directory
            .get_or_init(|| self.provider.lookup(pid))
            .clone()
    }

    fn entry_point(&self, pid: Option<u32>, pid_version: Option<u32>) -> Option<String> {
        let pid = pid?;
        // Without an incarnation identifier, never reuse a cached entry script
        // for a PID that the OS may have reassigned to another process.
        if pid_version.is_none() {
            return self.provider.entry_point(pid, None);
        }
        self.entry(ProcessIdentity { pid, pid_version })
            .entry_point
            .get_or_init(|| self.provider.entry_point(pid, pid_version))
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use std::{
        path::PathBuf,
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        thread,
        time::Duration,
    };

    use super::{CachedProcessContextResolver, ProcessContextProvider};
    use crate::process_context::ProcessContextResolver;

    struct CountingProvider {
        calls: AtomicUsize,
        result: Option<PathBuf>,
    }

    impl ProcessContextProvider for CountingProvider {
        fn lookup(&self, _pid: u32) -> Option<PathBuf> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            self.result.clone()
        }
    }

    #[test]
    fn same_process_identity_uses_one_lookup_for_multiple_flows() {
        let resolver = CachedProcessContextResolver::new(CountingProvider {
            calls: AtomicUsize::new(0),
            result: Some(PathBuf::from("/tmp/project")),
        });

        assert_eq!(
            resolver.working_directory(Some(42), Some(7)),
            Some(PathBuf::from("/tmp/project"))
        );
        assert_eq!(
            resolver.working_directory(Some(42), Some(7)),
            Some(PathBuf::from("/tmp/project"))
        );
        assert_eq!(resolver.provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn pid_version_separates_reused_process_ids() {
        let resolver = CachedProcessContextResolver::new(CountingProvider {
            calls: AtomicUsize::new(0),
            result: Some(PathBuf::from("/tmp/project")),
        });

        assert!(resolver.working_directory(Some(42), Some(7)).is_some());
        assert!(resolver.working_directory(Some(42), Some(8)).is_some());
        assert_eq!(resolver.provider.calls.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn failed_lookup_is_cached_for_the_same_process_identity() {
        let resolver = CachedProcessContextResolver::new(CountingProvider {
            calls: AtomicUsize::new(0),
            result: None,
        });

        assert_eq!(resolver.working_directory(Some(42), Some(7)), None);
        assert_eq!(resolver.working_directory(Some(42), Some(7)), None);
        assert_eq!(resolver.provider.calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn missing_pid_does_not_call_the_platform_provider() {
        let resolver = CachedProcessContextResolver::new(CountingProvider {
            calls: AtomicUsize::new(0),
            result: Some(PathBuf::from("/tmp/project")),
        });

        assert_eq!(resolver.working_directory(None, Some(7)), None);
        assert_eq!(resolver.provider.calls.load(Ordering::Relaxed), 0);
    }

    struct SlowCountingProvider {
        calls: AtomicUsize,
    }

    impl ProcessContextProvider for SlowCountingProvider {
        fn lookup(&self, _pid: u32) -> Option<PathBuf> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            thread::sleep(Duration::from_millis(10));
            Some(PathBuf::from("/tmp/project"))
        }
    }

    #[test]
    fn concurrent_flows_share_the_first_process_lookup() {
        let resolver = Arc::new(CachedProcessContextResolver::new(SlowCountingProvider {
            calls: AtomicUsize::new(0),
        }));
        let workers = std::iter::repeat_with(|| {
            let resolver = resolver.clone();
            thread::spawn(move || resolver.working_directory(Some(42), Some(7)))
        })
        .take(8_usize)
        .collect::<Vec<_>>();

        for worker in workers {
            assert_eq!(
                worker.join().expect("lookup worker should not panic"),
                Some(PathBuf::from("/tmp/project"))
            );
        }
        assert_eq!(resolver.provider.calls.load(Ordering::Relaxed), 1);
    }

    struct ConcurrentProvider {
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl ProcessContextProvider for ConcurrentProvider {
        fn lookup(&self, pid: u32) -> Option<PathBuf> {
            let active = self.active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            self.max_active.fetch_max(active, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(20));
            self.active.fetch_sub(1, Ordering::SeqCst);
            Some(PathBuf::from(format!("/tmp/project-{pid}")))
        }
    }

    #[test]
    fn different_processes_do_not_serialize_native_lookups() {
        let resolver = Arc::new(CachedProcessContextResolver::new(ConcurrentProvider {
            active: AtomicUsize::new(0),
            max_active: AtomicUsize::new(0),
        }));
        let start = Arc::new(Barrier::new(3));
        let workers = [42_u32, 43_u32].map(|pid| {
            let resolver = resolver.clone();
            let start = start.clone();
            thread::spawn(move || {
                start.wait();
                resolver.working_directory(Some(pid), Some(7))
            })
        });
        start.wait();

        for (worker, pid) in workers.into_iter().zip([42_u32, 43_u32]) {
            assert_eq!(
                worker.join().expect("lookup worker should not panic"),
                Some(PathBuf::from(format!("/tmp/project-{pid}")))
            );
        }
        assert_eq!(resolver.provider.max_active.load(Ordering::SeqCst), 2);
    }

    struct EntryPointProvider(AtomicUsize);

    impl ProcessContextProvider for EntryPointProvider {
        fn lookup(&self, _pid: u32) -> Option<PathBuf> {
            None
        }
        fn entry_point(&self, _pid: u32, version: Option<u32>) -> Option<String> {
            self.0.fetch_add(1, Ordering::Relaxed);
            version.map(|version| format!("/tmp/entry-{version}.js"))
        }
    }

    #[test]
    fn entry_points_cache_by_incarnation_and_do_not_cache_unversioned_pids() {
        let resolver = CachedProcessContextResolver::new(EntryPointProvider(AtomicUsize::new(0)));
        assert_eq!(
            resolver.entry_point(Some(42), Some(7)),
            Some("/tmp/entry-7.js".to_owned())
        );
        assert_eq!(
            resolver.entry_point(Some(42), Some(7)),
            Some("/tmp/entry-7.js".to_owned())
        );
        assert_eq!(
            resolver.entry_point(Some(42), Some(8)),
            Some("/tmp/entry-8.js".to_owned())
        );
        assert_eq!(resolver.provider.0.load(Ordering::Relaxed), 2);
        assert_eq!(resolver.entry_point(None, None), None);
        assert_eq!(resolver.entry_point(Some(42), None), None);
        assert_eq!(resolver.entry_point(Some(42), None), None);
        assert_eq!(resolver.provider.0.load(Ordering::Relaxed), 4);
    }
}
