//! Conservative Node/Electron entry-script identification from native argv.
//!
//! Only a positively identified script is retained. Options, script arguments,
//! and environment variables never become process metadata or matching inputs.

use std::path::{Component, Path};

pub(super) struct RuntimeEntryPoint;

impl RuntimeEntryPoint {
    pub(super) fn resolve(executable: &str, arguments: &[&str]) -> Option<String> {
        if !matches!(
            Path::new(executable).file_name()?.to_str()?,
            "Electron" | "node" | "nodejs"
        ) {
            return None;
        }
        let mut arguments = arguments.iter().skip(1);
        let script = loop {
            let argument = *arguments.next()?;
            match argument {
                "--" => break *arguments.next()?,
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
                path => break path,
            }
        };
        let script = normalized_absolute_path(script)?;
        let executable = normalized_absolute_path(executable)?;
        let executable_path = Path::new(&executable);
        let bundle = executable_path
            .ancestors()
            .find(|path| path.extension().is_some_and(|ext| ext == "app"));
        if let Some(bundle) = bundle {
            // Only the same bundle can produce bundle-relative metadata. An
            // external script must not masquerade as the app's bundled entry.
            let relative = Path::new(&script).strip_prefix(bundle).ok()?;
            if !relative.starts_with("Contents") {
                return None;
            }
            return relative.to_str().map(str::to_owned);
        }
        Some(script)
    }
}

fn normalized_absolute_path(value: &str) -> Option<String> {
    let path = Path::new(value);
    if !path.is_absolute() || value.chars().any(char::is_control) {
        return None;
    }
    let mut parts = Vec::new();
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(value) => parts.push(value.to_str()?),
            // Avoid resolving symlinks or a lexical `..` across a bundle boundary.
            Component::ParentDir | Component::Prefix(_) => return None,
        }
    }
    (!parts.is_empty()).then(|| format!("/{}", parts.join("/")))
}

#[cfg(test)]
mod tests {
    use super::RuntimeEntryPoint;

    #[test]
    fn bundled_entries_are_exact_and_independent_of_install_location() {
        for bundle in [
            "/Applications/Example.app",
            "/Users/test/My Apps/Example.app",
        ] {
            let exe = format!("{bundle}/Contents/MacOS/Electron");
            for relative in [
                "Contents/Resources/app.asar/main/daemon.js",
                "Contents/Resources/app.asar.unpacked/cli/bin/agent",
            ] {
                let script = format!("{bundle}/{relative}");
                assert_eq!(
                    RuntimeEntryPoint::resolve(
                        &exe,
                        &[
                            &exe,
                            "--optimize-for-size",
                            "--max-semi-space-size=2",
                            &script,
                            "--token",
                            "not-metadata"
                        ]
                    ),
                    Some(relative.to_owned())
                );
            }
        }
    }

    #[test]
    fn does_not_mistake_option_values_or_script_arguments_for_entry_points() {
        let exe = "/Applications/Example.app/Contents/MacOS/Electron";
        let script = "/Applications/Example.app/Contents/Resources/daemon.js";
        for args in [
            vec![exe],
            vec![exe, "--type=renderer", script],
            vec![exe, "-e", script],
            vec![exe, "--require", script],
            vec![exe, "--unknown", script],
            vec![exe, "--max-old-space-size=invalid", script],
        ] {
            assert_eq!(RuntimeEntryPoint::resolve(exe, &args), None);
        }
        assert_eq!(
            RuntimeEntryPoint::resolve(exe, &[exe, script, "/another.js"]),
            Some("Contents/Resources/daemon.js".to_owned())
        );
    }

    #[test]
    fn rejects_relative_external_and_parent_traversal_scripts() {
        let exe = "/Applications/Example.app/Contents/MacOS/Electron";
        for script in [
            "daemon.js",
            "/tmp/Example.app/Contents/Resources/daemon.js",
            "/Applications/Example.app.evil/Contents/Resources/daemon.js",
            "/Applications/Example.app/Contents/../daemon.js",
            "/Applications/Example.app/daemon.js",
        ] {
            assert_eq!(RuntimeEntryPoint::resolve(exe, &[exe, script]), None);
        }
    }

    #[test]
    fn standalone_node_retains_normalized_absolute_entry_only() {
        assert_eq!(
            RuntimeEntryPoint::resolve(
                "/usr/bin/node",
                &["node", "--", "/tmp//project/./agent.js", "secret"]
            ),
            Some("/tmp/project/agent.js".to_owned())
        );
        assert_eq!(
            RuntimeEntryPoint::resolve("/bin/cat", &["cat", "/tmp/agent.js"]),
            None
        );
    }
}
