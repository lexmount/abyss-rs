//! Shared process-identity cache for platform working-directory providers.

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
    expires_at: Instant,
}

pub(super) trait WorkingDirectoryProvider: Send + Sync {
    fn lookup(&self, pid: u32) -> Option<PathBuf>;
}

pub(super) struct CachedProcessContextResolver<P> {
    provider: P,
    entries: Mutex<HashMap<ProcessIdentity, Arc<CacheEntry>>>,
}

impl<P> CachedProcessContextResolver<P>
where
    P: WorkingDirectoryProvider,
{
    pub(super) fn new(provider: P) -> Self {
        Self {
            provider,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn resolve(&self, identity: ProcessIdentity) -> Option<PathBuf> {
        let now = Instant::now();
        let pid = identity.pid;
        let entry = {
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
                    expires_at,
                });
                entries.insert(identity, Arc::clone(&entry));
                entry
            }
        };

        entry
            .working_directory
            .get_or_init(|| self.provider.lookup(pid))
            .clone()
    }
}

impl<P> ProcessContextResolver for CachedProcessContextResolver<P>
where
    P: WorkingDirectoryProvider,
{
    fn working_directory(&self, pid: Option<u32>, pid_version: Option<u32>) -> Option<PathBuf> {
        self.resolve(ProcessIdentity {
            pid: pid?,
            pid_version,
        })
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

    use super::{CachedProcessContextResolver, WorkingDirectoryProvider};
    use crate::process_context::ProcessContextResolver;

    struct CountingProvider {
        calls: AtomicUsize,
        result: Option<PathBuf>,
    }

    impl WorkingDirectoryProvider for CountingProvider {
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

    impl WorkingDirectoryProvider for SlowCountingProvider {
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

    impl WorkingDirectoryProvider for ConcurrentProvider {
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
}
