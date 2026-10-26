//! Lexical normalization of absolute entry paths for exact policy matching.
//!
//! No filesystem, symlink or module search is performed. Relative targets cannot
//! be resolved reliably from a process's possibly changed working directory.

use std::path::{Path, PathBuf};

pub(super) struct ScriptPath;

impl ScriptPath {
    pub(super) fn resolve(executable: &str, target: &str) -> Option<String> {
        let target = Path::new(target);
        if !Path::new(executable).is_absolute() || !target.is_absolute() {
            return None;
        }
        target
            .components()
            .collect::<PathBuf>()
            .to_str()
            .map(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::ScriptPath;

    #[test]
    fn absolute_paths_are_normalized_without_accessing_the_filesystem() {
        let root = std::env::temp_dir();
        let executable = root.join("node");
        let script = root.join("My Project").join("main.js");
        assert_eq!(
            ScriptPath::resolve(
                executable.to_str().unwrap(),
                &format!("{}//My Project/./main.js", root.display())
            ),
            Some(script.to_str().unwrap().to_owned())
        );
        for target in ["relative.js", "Contents/Resources/main.js"] {
            assert!(ScriptPath::resolve(executable.to_str().unwrap(), target).is_none());
        }
        assert!(ScriptPath::resolve("node", script.to_str().unwrap()).is_none());
    }

    #[test]
    fn app_directories_preserve_full_script_paths() {
        let root = std::env::temp_dir();
        for bundle in [
            root.join("Example.app"),
            root.join("My Apps").join("Example.app"),
        ] {
            let executable = bundle.join("Contents/MacOS/Electron");
            for target in [
                bundle.join("Contents").join("Resources").join("main.js"),
                root.join("outside").join("main.js"),
            ] {
                assert_eq!(
                    ScriptPath::resolve(executable.to_str().unwrap(), target.to_str().unwrap()),
                    Some(target.to_str().unwrap().to_owned())
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_absolute_entries_preserve_drive_and_unc_prefixes() {
        for target in [r"C:\Agent\main.js", r"\\server\share\Agent\main.js"] {
            assert_eq!(
                ScriptPath::resolve(r"C:\Node\node.exe", target).as_deref(),
                Some(target)
            );
        }
        for target in [r"C:Agent\main.js", r"\Agent\main.js"] {
            assert!(ScriptPath::resolve(r"C:\Node\node.exe", target).is_none());
        }
    }
}
