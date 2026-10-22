//! Node/Electron command syntax for direct script launches; no application-specific rules.

use super::{RuntimeEntryPointResolver, path::ScriptPath};
use crate::process_context::process_arguments::ProcessArguments;

pub(super) struct NodeEntryPoint;

impl RuntimeEntryPointResolver for NodeEntryPoint {
    fn recognizes(&self, executable: &str) -> bool {
        matches!(
            executable.rsplit(['/', '\\']).next(),
            Some("Electron" | "electron" | "electron.exe" | "node" | "nodejs" | "node.exe")
        )
    }

    fn parse_command<'a>(&self, arguments: &'a ProcessArguments) -> Option<&'a str> {
        let mut arguments = arguments.argv.iter().skip(1).map(String::as_str);
        loop {
            match arguments.next()? {
                "--" => return arguments.next(),
                "--optimize-for-size" | "--no-warnings" | "--enable-source-maps" => {}
                option
                    if ["--max-semi-space-size=", "--max-old-space-size="]
                        .iter()
                        .any(|prefix| {
                            option.strip_prefix(prefix).is_some_and(|value| {
                                !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
                            })
                        }) => {}
                // Unknown options may consume the next argument or select eval,
                // print, a renderer, or another execution mode. Do not guess.
                option if option.starts_with('-') => return None,
                path => return Some(path),
            }
        }
    }

    fn execution_path(&self, executable: &str, target: &str) -> Option<String> {
        ScriptPath::resolve(executable, target)
    }
}

#[cfg(test)]
mod tests {
    use super::{NodeEntryPoint, ProcessArguments, RuntimeEntryPointResolver};

    #[test]
    fn recognizes_runtime_names_without_inspecting_script_arguments() {
        for executable in [
            "/usr/bin/node",
            "/usr/bin/nodejs",
            "/Applications/A.app/Contents/MacOS/Electron",
            "C:\\Node\\node.exe",
        ] {
            assert!(NodeEntryPoint.recognizes(executable));
        }
        for executable in ["/bin/cat", "/usr/bin/python3", "/usr/bin/node-helper"] {
            assert!(!NodeEntryPoint.recognizes(executable));
        }
    }

    #[test]
    fn runtime_options_are_skipped_but_script_arguments_are_not_inspected() {
        let command = ProcessArguments {
            executable: "/usr/bin/node".to_owned(),
            argv: [
                "node",
                "--no-warnings",
                "--max-semi-space-size=2",
                "/opt/daemon.js",
                "--token",
                "not-metadata",
                "/other.js",
            ]
            .map(str::to_owned)
            .to_vec(),
        };
        assert_eq!(
            NodeEntryPoint.parse_command(&command),
            Some("/opt/daemon.js")
        );
    }

    #[test]
    fn option_values_and_other_execution_modes_are_not_script_entries() {
        for args in [
            vec!["node"],
            vec!["node", "-e", "/opt/daemon.js"],
            vec!["node", "-p", "/opt/daemon.js"],
            vec!["node", "--require", "/opt/daemon.js"],
            vec!["node", "--type=renderer", "/opt/daemon.js"],
            vec!["node", "--unknown", "/opt/daemon.js"],
            vec!["node", "--max-old-space-size=invalid", "/opt/daemon.js"],
            vec!["node", "-"],
            vec!["node", "--"],
        ] {
            let command = ProcessArguments {
                executable: "/usr/bin/node".to_owned(),
                argv: args.iter().map(|arg| (*arg).to_owned()).collect(),
            };
            assert!(NodeEntryPoint.parse_command(&command).is_none(), "{args:?}");
        }
    }
}
