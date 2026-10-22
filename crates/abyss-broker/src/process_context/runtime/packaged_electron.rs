//! Explicit packaged Electron runtime identities sharing Node's direct-script syntax.
//!
//! These names identify supported launch forms, not executable integrity. Unknown
//! applications and Chromium child-process switches are never guessed from paths.

use super::{RuntimeEntryPointResolver, node::NodeEntryPoint};
use crate::process_context::process_arguments::ProcessArguments;

pub(super) struct PackagedElectronEntryPoint;

impl RuntimeEntryPointResolver for PackagedElectronEntryPoint {
    fn recognizes(&self, executable: &str) -> bool {
        executable.rsplit(['/', '\\']).next().is_some_and(|name| {
            ["WorkBuddy.exe", "WorkBuddyAI.exe"]
                .iter()
                .any(|known| name.eq_ignore_ascii_case(known))
        })
    }

    fn parse_command<'a>(&self, arguments: &'a ProcessArguments) -> Option<&'a str> {
        NodeEntryPoint.parse_command(arguments)
    }

    fn execution_path(&self, executable: &str, target: &str) -> Option<String> {
        NodeEntryPoint.execution_path(executable, target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packaged_identity_is_exact_and_accepts_windows_casing() {
        for name in [
            r"C:\WorkBuddy\WorkBuddyAI.exe",
            r"C:\Apps\workbuddyai.exe",
            "WORKBUDDY.EXE",
        ] {
            assert!(PackagedElectronEntryPoint.recognizes(name));
        }
        for name in [
            "Unknown.exe",
            "OtherWorkBuddyAI.exe",
            "WorkBuddyAI.exe.bak",
            r"C:\WorkBuddyAI.exe\other.exe",
        ] {
            assert!(!PackagedElectronEntryPoint.recognizes(name));
        }
    }

    #[test]
    fn daemon_and_extensionless_cli_share_direct_script_parsing() {
        for (argv, expected) in [
            (
                vec![
                    "WorkBuddyAI.exe",
                    r"C:\WorkBuddy\main\daemon-app-server-entry.js",
                ],
                Some(r"C:\WorkBuddy\main\daemon-app-server-entry.js"),
            ),
            (
                vec![
                    "WorkBuddyAI.exe",
                    "--optimize-for-size",
                    "--max-semi-space-size=2",
                    r"C:\WorkBuddy\cli\bin\codebuddy",
                    "--prewarm",
                    "private-value",
                ],
                Some(r"C:\WorkBuddy\cli\bin\codebuddy"),
            ),
            (
                vec![
                    "WorkBuddyAI.exe",
                    "--type=renderer",
                    r"C:\WorkBuddy\main.js",
                ],
                None,
            ),
            (
                vec!["WorkBuddyAI.exe", "--type=utility", r"C:\WorkBuddy\main.js"],
                None,
            ),
            (vec!["WorkBuddyAI.exe", "-e", r"C:\WorkBuddy\main.js"], None),
            (vec!["WorkBuddyAI.exe"], None),
        ] {
            let arguments = ProcessArguments {
                executable: r"C:\WorkBuddy\WorkBuddyAI.exe".to_owned(),
                argv: argv.into_iter().map(str::to_owned).collect(),
            };
            assert_eq!(
                PackagedElectronEntryPoint.parse_command(&arguments),
                expected
            );
        }
    }
}
