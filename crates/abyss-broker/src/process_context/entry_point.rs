//! Shared pipeline: read startup arguments, select a runtime, parse and resolve its entry.
//!
//! Platform readers and runtime parsers are injected as trait objects. Full argv
//! stays transient; only an identified execution path leaves this pipeline.

use super::{
    process_arguments::ProcessArgumentsProvider,
    runtime::{RuntimeEntryPointResolver, runtime_resolvers},
};

pub(super) struct EntryPointResolver {
    arguments: Box<dyn ProcessArgumentsProvider>,
    runtimes: Vec<Box<dyn RuntimeEntryPointResolver>>,
}

impl EntryPointResolver {
    pub(super) fn new(arguments: Box<dyn ProcessArgumentsProvider>) -> Self {
        Self {
            arguments,
            runtimes: runtime_resolvers(),
        }
    }

    pub(super) fn resolve(&self, pid: Option<u32>) -> Option<String> {
        // Always refresh: a PID can be reused or execute another program.
        let arguments = self.arguments.read(pid?).ok()?;
        let runtime = self
            .runtimes
            .iter()
            .find(|runtime| runtime.recognizes(&arguments.executable))?;
        let target = runtime.parse_command(&arguments)?;
        runtime.execution_path(&arguments.executable, target)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use super::{EntryPointResolver, ProcessArgumentsProvider, RuntimeEntryPointResolver};
    use crate::process_context::process_arguments::ProcessArguments;

    #[cfg(not(windows))]
    const NODE: &str = "/usr/bin/node";
    #[cfg(windows)]
    const NODE: &str = r"C:\Node\node.exe";
    #[cfg(not(windows))]
    const DAEMON: &str = "/opt/daemon.js";
    #[cfg(windows)]
    const DAEMON: &str = r"C:\Agent\daemon.js";
    #[cfg(not(windows))]
    const CLI: &str = "/opt/cli.js";
    #[cfg(windows)]
    const CLI: &str = r"C:\Agent\cli.js";

    struct ArgumentsFixture {
        executable: &'static str,
        argv: Vec<&'static str>,
        calls: Arc<AtomicUsize>,
    }

    impl ProcessArgumentsProvider for ArgumentsFixture {
        fn read(&self, _pid: u32) -> io::Result<ProcessArguments> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(ProcessArguments {
                executable: self.executable.to_owned(),
                argv: self.argv.iter().map(|arg| (*arg).to_owned()).collect(),
            })
        }
    }

    #[test]
    fn shared_pipeline_selects_runtimes_and_never_uses_business_arguments() {
        for (executable, argv, expected) in [
            (NODE, vec!["node", "--", DAEMON, "secret"], Some(DAEMON)),
            ("/usr/bin/python3", vec!["python3", "/opt/task.py"], None),
            (NODE, vec!["node", "--unknown", "/opt/fake.js"], None),
            ("/bin/cat", vec!["node", "/opt/fake.js"], None),
        ] {
            let calls = Arc::new(AtomicUsize::new(0));
            let resolver = EntryPointResolver::new(Box::new(ArgumentsFixture {
                executable,
                argv,
                calls: calls.clone(),
            }));
            assert_eq!(resolver.resolve(Some(42)).as_deref(), expected);
            assert_eq!(calls.load(Ordering::Relaxed), 1);
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_packaged_runtime_preserves_absolute_paths_and_ignores_business_arguments() {
        const EXECUTABLE: &str = r"C:\Program Files\WorkBuddy\WorkBuddyAI.exe";
        const ENTRY: &str = r"C:\Program Files\WorkBuddy\资源\cli\bin\codebuddy";
        for (argv, expected) in [
            (
                vec![
                    EXECUTABLE,
                    "--optimize-for-size",
                    "--max-semi-space-size=2",
                    ENTRY,
                    "--prewarm",
                    "secret",
                ],
                Some(ENTRY),
            ),
            (vec![EXECUTABLE, "--type=utility", ENTRY], None),
            (vec![EXECUTABLE, "relative.js", ENTRY], None),
            (vec![EXECUTABLE, "-e", ENTRY], None),
        ] {
            let resolver = EntryPointResolver::new(Box::new(ArgumentsFixture {
                executable: EXECUTABLE,
                argv,
                calls: Arc::new(AtomicUsize::new(0)),
            }));
            assert_eq!(resolver.resolve(Some(42)).as_deref(), expected);
        }
    }

    struct ChangingArguments(Arc<AtomicUsize>);

    impl ProcessArgumentsProvider for ChangingArguments {
        fn read(&self, _pid: u32) -> io::Result<ProcessArguments> {
            let entry = match self.0.fetch_add(1, Ordering::Relaxed) {
                0 => DAEMON,
                1 => CLI,
                _ => return Err(io::Error::new(io::ErrorKind::NotFound, "process exited")),
            };
            Ok(ProcessArguments {
                executable: NODE.to_owned(),
                argv: vec!["node".to_owned(), entry.to_owned()],
            })
        }
    }

    #[test]
    fn missing_pid_is_not_queried_and_reused_pid_does_not_reuse_an_entry() {
        let calls = Arc::new(AtomicUsize::new(0));
        let resolver = EntryPointResolver::new(Box::new(ChangingArguments(calls.clone())));
        assert_eq!(resolver.resolve(None), None);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        assert_eq!(resolver.resolve(Some(42)).as_deref(), Some(DAEMON));
        assert_eq!(resolver.resolve(Some(42)).as_deref(), Some(CLI));
        assert_eq!(resolver.resolve(Some(42)), None);
        assert_eq!(calls.load(Ordering::Relaxed), 3);
    }

    struct AdditionalRuntime;

    impl RuntimeEntryPointResolver for AdditionalRuntime {
        fn recognizes(&self, executable: &str) -> bool {
            executable == "/opt/another-runtime"
        }
        fn parse_command<'a>(&self, arguments: &'a ProcessArguments) -> Option<&'a str> {
            arguments.argv.get(2).map(String::as_str)
        }
        fn execution_path(&self, _executable: &str, target: &str) -> Option<String> {
            Some(format!("/opt/{target}"))
        }
    }

    #[test]
    fn another_runtime_can_be_injected_without_changing_the_pipeline() {
        let mut resolver = EntryPointResolver::new(Box::new(ArgumentsFixture {
            executable: "/opt/another-runtime",
            argv: vec!["runtime", "run", "task"],
            calls: Arc::new(AtomicUsize::new(0)),
        }));
        assert_eq!(resolver.resolve(Some(42)), None);
        resolver.runtimes.push(Box::new(AdditionalRuntime));
        assert_eq!(resolver.resolve(Some(42)).as_deref(), Some("/opt/task"));
    }
}
