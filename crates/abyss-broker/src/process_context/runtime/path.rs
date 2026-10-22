//! Lexical normalization of absolute entry paths for exact policy matching.
//!
//! No filesystem, symlink or module search is performed. Relative targets cannot
//! be resolved reliably from a process's possibly changed working directory.

pub(super) struct ScriptPath;

impl ScriptPath {
    pub(super) fn resolve(executable: &str, target: &str) -> Option<String> {
        Self::absolute(executable)?;
        Self::absolute(target)
    }

    fn absolute(value: &str) -> Option<String> {
        // Current policy paths are normalized absolute POSIX paths.
        // Keep this lexical representation independent of the host's Path parser.
        if !value.starts_with('/')
            || value.chars().any(char::is_control)
            || value.contains(['\\', '*', '?'])
        {
            return None;
        }
        let mut parts = Vec::new();
        for part in value.split('/') {
            match part {
                "" | "." => {}
                ".." => return None,
                part => parts.push(part),
            }
        }
        (!parts.is_empty()).then(|| format!("/{}", parts.join("/")))
    }
}

#[cfg(test)]
mod tests {
    use super::ScriptPath;

    #[test]
    fn standalone_paths_are_normalized_without_guessing() {
        assert_eq!(
            ScriptPath::resolve("/usr/bin/node", "/tmp//My Project/./main.js"),
            Some("/tmp/My Project/main.js".to_owned())
        );
        for path in [
            "relative.js",
            "/tmp/../main.js",
            "/",
            "/tmp/secret\n.js",
            "/tmp/*.js",
        ] {
            assert!(ScriptPath::resolve("/usr/bin/node", path).is_none());
        }
    }

    #[test]
    fn app_directories_preserve_full_script_paths() {
        for bundle in [
            "/Applications/Example.app",
            "/Users/test/My Apps/Example.app",
        ] {
            let executable = format!("{bundle}/Contents/MacOS/Electron");
            for target in [
                format!("{bundle}/Contents/Resources/main.js"),
                "/tmp/Example.app/Contents/Resources/main.js".to_owned(),
                format!("{bundle}.evil/Contents/Resources/main.js"),
                format!("{bundle}/main.js"),
            ] {
                assert_eq!(ScriptPath::resolve(&executable, &target), Some(target));
            }
        }
    }
}
