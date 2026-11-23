//! Python `-m` entry attribution using the shared native argv pipeline.
//!
//! Only the interpreter's execution mode is inspected. Script/inline code and
//! arguments after the module cannot identify a module, and nothing is imported.

use abyss_mitm::ModuleRuntime;

use super::{ProcessEntry, RuntimeEntryPointResolver};
use crate::process_context::process_arguments::ProcessArguments;

pub(super) struct PythonEntryPoint;

impl RuntimeEntryPointResolver for PythonEntryPoint {
    fn recognizes(&self, executable: &str) -> bool {
        let name = executable.rsplit(['/', '\\']).next().unwrap_or_default();
        let normalized = name.to_ascii_lowercase();
        let name = normalized.strip_suffix(".exe").unwrap_or(&normalized);
        let Some(version) = name
            .strip_prefix("pythonw")
            .or_else(|| name.strip_prefix("python"))
        else {
            return false;
        };
        version.is_empty()
            || version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    }

    fn resolve_entry(&self, arguments: &ProcessArguments) -> Option<ProcessEntry> {
        let mut args = arguments.argv.iter().skip(1).map(String::as_str);
        while let Some(argument) = args.next() {
            // A first script, stdin marker or `--` ends interpreter options.
            let options = argument.strip_prefix('-')?;
            if options.is_empty() || options.starts_with('-') {
                return None;
            }
            let mut options = options.chars();
            while let Some(option) = options.next() {
                match option {
                    'm' => {
                        let remaining = options.as_str();
                        let module = if remaining.is_empty() {
                            args.next()?
                        } else {
                            remaining
                        };
                        return ProcessEntry::module(ModuleRuntime::Python, module.to_owned()).ok();
                    }
                    // These options consume a value, so it must never be scanned as a mode.
                    'W' | 'X' => {
                        if options.as_str().is_empty() {
                            args.next()?;
                        }
                        break;
                    }
                    'b' | 'B' | 'd' | 'E' | 'i' | 'I' | 'O' | 'P' | 'q' | 's' | 'S' | 'u' | 'v'
                    | 'x' => {}
                    // Includes -c, help/version, unknown flags and future execution modes.
                    _ => return None,
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn module(argv: &[&str]) -> Option<String> {
        let arguments = ProcessArguments {
            executable: "C:\\Python\\python.exe".to_owned(),
            argv: argv.iter().map(|value| (*value).to_owned()).collect(),
        };
        match PythonEntryPoint.resolve_entry(&arguments)? {
            ProcessEntry::Module { name, .. } => Some(name),
            _ => panic!("Python module parser returned a non-module entry"),
        }
    }

    #[test]
    fn recognizes_interpreters_but_not_launchers_or_lookalikes() {
        for name in [
            "python.exe",
            "PYTHONW.EXE",
            "python",
            "python3",
            "/usr/bin/python3.14",
        ] {
            assert!(PythonEntryPoint.recognizes(name), "{name}");
        }
        for name in [
            "py.exe",
            "hermes.exe",
            "notpython.exe",
            "python.exe.bak",
            "python-helper",
            "python3.",
        ] {
            assert!(!PythonEntryPoint.recognizes(name), "{name}");
        }
    }

    #[test]
    fn module_mode_preserves_boundaries_and_excludes_application_arguments() {
        for argv in [
            vec![
                "python",
                "-m",
                "hermes_cli.main",
                "--profile",
                "secret",
                "gateway",
                "run",
            ],
            vec!["python", "-I", "-u", "-m", "hermes_cli.main"],
            vec!["python", "-Iumhermes_cli.main", "-c", "secret"],
            vec!["python", "-W", "ignore", "-Xutf8", "-mhermes_cli.main"],
            vec!["python", "-X", "dev", "-m", "hermes_cli.main"],
        ] {
            assert_eq!(
                module(&argv).as_deref(),
                Some("hermes_cli.main"),
                "{argv:?}"
            );
        }
        assert_eq!(
            module(&["python", "-m", "other", "-m", "hermes_cli.main"]).as_deref(),
            Some("other")
        );
    }

    #[test]
    fn scripts_inline_code_and_option_values_cannot_spoof_a_module() {
        for argv in [
            vec!["python", "-c", "secret", "-m", "hermes_cli.main"],
            vec!["python", "-csecret", "-m", "hermes_cli.main"],
            vec!["python", "task.py", "-m", "hermes_cli.main"],
            vec!["python", "--", "-m", "hermes_cli.main"],
            vec!["python", "-", "-m", "hermes_cli.main"],
            vec!["python", "-W", "-m", "hermes_cli.main"],
            vec!["python", "-X-mhermes_cli.main"],
            vec!["python", "--unknown", "-m", "hermes_cli.main"],
            vec!["python", "-V", "-m", "hermes_cli.main"],
            vec!["python", "-m"],
            vec!["python", "-m", "hermes_cli.main/other"],
        ] {
            assert!(module(&argv).is_none(), "{argv:?}");
        }
    }
}
