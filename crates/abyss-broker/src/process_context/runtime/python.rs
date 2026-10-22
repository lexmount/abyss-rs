//! `CPython` direct-script command interpretation; modules, inline code and stdin have no path.

use super::{RuntimeEntryPointResolver, path::ScriptPath};
use crate::sys::ProcessArguments;

pub(super) struct PythonEntryPoint;

impl RuntimeEntryPointResolver for PythonEntryPoint {
    fn recognizes(&self, executable: &str) -> bool {
        let name = executable.rsplit(['/', '\\']).next().unwrap_or_default();
        let name = name.strip_suffix(".exe").unwrap_or(name);
        if matches!(name, "python" | "Python") {
            return true;
        }
        name.strip_prefix("python").is_some_and(|version| {
            !version.is_empty()
                && version
                    .split('.')
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
        })
    }

    fn parse_command<'a>(&self, arguments: &'a ProcessArguments) -> Option<&'a str> {
        let mut arguments = arguments.argv.iter().skip(1).map(String::as_str);
        loop {
            match arguments.next()? {
                "--" => return arguments.next(),
                "-W" | "-X" => {
                    arguments.next()?;
                }
                option if option.starts_with("-W") || option.starts_with("-X") => {}
                "--check-hash-based-pycs" => {
                    if !matches!(arguments.next()?, "default" | "always" | "never") {
                        return None;
                    }
                }
                option
                    if option.strip_prefix('-').is_some_and(|flags| {
                        !flags.is_empty()
                            && flags.chars().all(|flag| "bBdEiIOPqRsSuvx".contains(flag))
                    }) => {}
                // -m needs Python's import search; -c/stdin are code, not paths.
                // Unknown and combined value-taking options are not guessed.
                option if option.starts_with('-') => return None,
                path => return Some(path),
            }
        }
    }

    fn execution_path(&self, executable: &str, target: &str) -> Option<String> {
        // A framework Python interpreter may itself live inside Python.app while
        // launching user scripts outside that bundle. Its script stays absolute.
        ScriptPath::absolute(executable)?;
        ScriptPath::absolute(target)
    }
}

#[cfg(test)]
mod tests {
    use super::{ProcessArguments, PythonEntryPoint, RuntimeEntryPointResolver};

    #[test]
    fn recognizes_python_names_and_numeric_versions_only() {
        for name in [
            "python",
            "python3",
            "python3.13",
            "Python",
            "python.exe",
            "python3.exe",
        ] {
            assert!(PythonEntryPoint.recognizes(&format!("/usr/bin/{name}")));
        }
        for name in [
            "python-config",
            "python3-config",
            "python3.",
            "python3..13",
            "node",
            "py",
        ] {
            assert!(!PythonEntryPoint.recognizes(&format!("/usr/bin/{name}")));
        }
    }

    #[test]
    fn framework_interpreters_keep_external_script_paths_absolute() {
        assert_eq!(
            PythonEntryPoint.execution_path(
                "/Library/Frameworks/Python.framework/Versions/3.13/Resources/Python.app/Contents/MacOS/Python",
                "/Users/test/My Project/agent.py",
            ),
            Some("/Users/test/My Project/agent.py".to_owned())
        );
        assert!(
            PythonEntryPoint
                .execution_path("/usr/bin/python3", "agent.py")
                .is_none()
        );
    }

    #[test]
    fn option_values_are_consumed_before_the_script() {
        for options in [
            vec!["-I", "-B"],
            vec!["-IB", "-W", "/not-an-entry.py", "-X", "dev"],
            vec!["-Wignore", "-Xdev"],
            vec!["--check-hash-based-pycs", "always"],
            vec!["--"],
        ] {
            let argv = std::iter::once("python3")
                .chain(options)
                .chain(["/opt/daemon.py", "-m", "secret"])
                .map(str::to_owned)
                .collect();
            let command = ProcessArguments {
                executable: "/usr/bin/python3".to_owned(),
                argv,
            };
            assert_eq!(
                PythonEntryPoint.parse_command(&command),
                Some("/opt/daemon.py")
            );
            assert_eq!(
                PythonEntryPoint.execution_path(&command.executable, "/opt/daemon.py"),
                Some("/opt/daemon.py".to_owned())
            );
        }
    }

    #[test]
    fn module_inline_stdin_and_incomplete_commands_do_not_invent_paths() {
        for options in [
            vec!["-m", "package", "/opt/fake.py"],
            vec!["-c", "code", "/opt/fake.py"],
            vec!["-Impackage", "/opt/fake.py"],
            vec!["-", "/opt/fake.py"],
            vec!["--version", "/opt/fake.py"],
            vec!["--unknown", "/opt/fake.py"],
            vec!["-W"],
            vec!["-X"],
            vec!["--"],
            vec!["--check-hash-based-pycs", "invalid", "/opt/fake.py"],
        ] {
            let argv = std::iter::once("python3")
                .chain(options)
                .map(str::to_owned)
                .collect();
            let command = ProcessArguments {
                executable: "/usr/bin/python3".to_owned(),
                argv,
            };
            assert!(PythonEntryPoint.parse_command(&command).is_none());
        }
    }
}
