//! Prepares child commands whose model connections must inherit the proxy.
//!
//! Codex can reuse a shared app-server started outside this launch environment.
//! Its supported foreground option keeps local inference in the proxied child.

use std::{path::Path, process::Command};

use crate::error::CliError;

/// Borrows the user's executable and arguments without changing global config.
pub struct AgentCommand<'a> {
    arguments: &'a [String],
}

impl<'a> AgentCommand<'a> {
    /// Uses the nonempty command validated by the CLI argument parser.
    pub const fn new(arguments: &'a [String]) -> Self {
        Self { arguments }
    }

    /// Builds a local agent command, isolating capable Codex versions.
    pub fn prepare(&self) -> Result<Command, CliError> {
        let mut command = Command::new(&self.arguments[0]);
        if self.needs_codex_isolation() {
            let help = Command::new(&self.arguments[0])
                .arg("--help")
                .output()
                .map_err(|source| {
                    CliError::filesystem("inspect Codex launch options", &self.arguments[0], source)
                })?;
            if !help.status.success() {
                return Err(CliError::Command {
                    program: format!("{} --help", self.arguments[0]),
                    status: help.status,
                    stderr: String::from_utf8_lossy(&help.stderr).trim().to_owned(),
                });
            }
            if Self::supports_foreground(&String::from_utf8_lossy(&help.stdout)) {
                command.arg("--no-daemon");
            }
        }
        command.args(&self.arguments[1..]);
        Ok(command)
    }

    fn needs_codex_isolation(&self) -> bool {
        if Path::new(&self.arguments[0])
            .file_name()
            .is_none_or(|name| name != "codex")
        {
            return false;
        }
        let mut arguments = self.arguments[1..].iter();
        let mut command_seen = false;
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--" => break,
                "--no-daemon" | "--remote" => return false,
                argument if argument.starts_with("--remote=") => return false,
                // Option values can themselves be named "queue" or "agents";
                // only the first positional argument selects a subcommand.
                "-c"
                | "--config"
                | "-C"
                | "--cd"
                | "-m"
                | "--model"
                | "-p"
                | "--profile"
                | "-s"
                | "--sandbox"
                | "-a"
                | "--ask-for-approval"
                | "--add-dir"
                | "--enable"
                | "--disable"
                | "-i"
                | "--image"
                | "--remote-auth-token-env" => {
                    if arguments.next().is_none() {
                        break;
                    }
                }
                argument if !argument.starts_with('-') && !command_seen => {
                    command_seen = true;
                    if matches!(argument, "queue" | "remote-control" | "agents") {
                        return false;
                    }
                }
                _ => {}
            }
        }
        true
    }

    fn supports_foreground(help: &str) -> bool {
        help.split_ascii_whitespace()
            .any(|word| word == "--no-daemon")
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt as _, path::PathBuf, time::SystemTime};

    use super::AgentCommand;

    #[test]
    fn direct_codex_and_absolute_paths_require_an_isolated_model_process() {
        for args in [
            vec!["codex"],
            vec!["/opt/codex/bin/codex", "resume", "--last"],
            vec!["codex", "exec", "hello"],
            vec!["codex", "--", "--no-daemon"],
            vec!["codex", "-C", "queue"],
            vec!["codex", "--model", "agents", "exec", "hello"],
            vec!["codex", "resume", "--last", "queue"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(AgentCommand::new(&args).needs_codex_isolation());
        }
    }

    #[test]
    fn explicit_server_operations_and_other_executables_keep_their_arguments() {
        for args in [
            vec!["dsh", "web"],
            vec!["my-codex", "hello"],
            vec!["codex", "--no-daemon", "resume", "--last"],
            vec!["codex", "--remote", "ws://localhost:9000"],
            vec!["codex", "--remote=unix://server.sock"],
            vec!["codex", "queue", "hello"],
            vec!["codex", "remote-control", "start"],
            vec!["codex", "agents"],
            vec!["codex", "-C", "workspace", "queue", "hello"],
        ] {
            let args = args.into_iter().map(str::to_owned).collect::<Vec<_>>();
            assert!(!AgentCommand::new(&args).needs_codex_isolation());
        }
    }

    #[test]
    fn capability_detection_requires_the_exact_supported_option() {
        assert!(AgentCommand::supports_foreground(
            "Options:\n  --no-daemon\n      Run without the shared background server\n"
        ));
        assert!(!AgentCommand::supports_foreground(
            "Options:\n  --model <MODEL>\n"
        ));
        assert!(!AgentCommand::supports_foreground("--no-daemon-other"));
    }

    #[test]
    fn supported_codex_executes_with_foreground_and_original_argument_boundaries() {
        let (root, executable) = codex_fixture("  --no-daemon");
        let arguments = vec![
            executable,
            "--".to_owned(),
            "a prompt with spaces".to_owned(),
        ];
        let output = AgentCommand::new(&arguments)
            .prepare()
            .expect("supported Codex should prepare")
            .output()
            .expect("prepared child should run");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"--no-daemon\n--\na prompt with spaces\n");
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn older_codex_executes_without_an_unsupported_option() {
        let (root, executable) = codex_fixture("  --model <MODEL>");
        let arguments = vec![executable, "exec".to_owned(), "hello".to_owned()];
        let output = AgentCommand::new(&arguments)
            .prepare()
            .expect("older Codex should prepare")
            .output()
            .expect("prepared child should run");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"exec\nhello\n");
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn explicit_foreground_is_not_probed_or_duplicated() {
        let (root, executable) = codex_fixture("unused");
        fs::write(
            &executable,
            "#!/bin/sh\n[ \"$1\" != --help ] || exit 42\nprintf '%s\\n' \"$@\"\n",
        )
        .expect("fixture should reject help probes");
        let arguments = vec![executable, "--no-daemon".to_owned(), "fork".to_owned()];
        let output = AgentCommand::new(&arguments)
            .prepare()
            .expect("explicit foreground should not probe Codex")
            .output()
            .expect("prepared child should run");

        assert!(output.status.success());
        assert_eq!(output.stdout, b"--no-daemon\nfork\n");
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    fn codex_fixture(help: &str) -> (PathBuf, String) {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("test clock should be valid")
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("abyss-codex-launch-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&root).expect("fixture directory should create");
        let executable = root.join("codex");
        fs::write(
            &executable,
            format!("#!/bin/sh\nif [ \"$1\" = --help ]; then\n  printf '%s\\n' '{help}'\n  exit 0\nfi\nprintf '%s\\n' \"$@\"\n"),
        )
        .expect("fixture executable should write");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))
            .expect("fixture should be executable");
        (
            root,
            executable
                .to_str()
                .expect("fixture path should be UTF-8")
                .to_owned(),
        )
    }
}
