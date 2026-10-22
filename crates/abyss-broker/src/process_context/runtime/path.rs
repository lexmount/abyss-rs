//! Lexical entry-path normalization, with macOS application-bundle representation.
//!
//! No filesystem, symlink or module search is performed. Relative targets cannot
//! be resolved reliably from a process's possibly changed working directory.

pub(super) struct ScriptPath;

impl ScriptPath {
    pub(super) fn resolve(executable: &str, target: &str) -> Option<String> {
        let executable = Self::absolute(executable)?;
        let script = Self::absolute(target)?;
        #[cfg(target_os = "macos")]
        {
            Self::macos_bundle_entry(&executable, &script)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = executable;
            Some(script)
        }
    }

    pub(super) fn absolute(value: &str) -> Option<String> {
        // Current policy paths are normalized POSIX paths or Contents/... paths.
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

    #[cfg(target_os = "macos")]
    fn macos_bundle_entry(executable: &str, script: &str) -> Option<String> {
        use std::path::Path;

        let bundle = Path::new(executable)
            .ancestors()
            .find(|path| path.extension().is_some_and(|ext| ext == "app"));
        if let Some(bundle) = bundle {
            // A script outside the executable's own bundle cannot claim a bundled role.
            let relative = Path::new(script).strip_prefix(bundle).ok()?;
            if !relative.starts_with("Contents") {
                return None;
            }
            return relative.to_str().map(str::to_owned);
        }
        Some(script.to_owned())
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

    #[cfg(target_os = "macos")]
    #[test]
    fn bundle_paths_are_installation_independent_and_stay_in_the_same_bundle() {
        for bundle in [
            "/Applications/Example.app",
            "/Users/test/My Apps/Example.app",
        ] {
            let executable = format!("{bundle}/Contents/MacOS/Electron");
            assert_eq!(
                ScriptPath::resolve(&executable, &format!("{bundle}/Contents/Resources/main.js")),
                Some("Contents/Resources/main.js".to_owned())
            );
            for target in [
                "/tmp/Example.app/Contents/Resources/main.js".to_owned(),
                format!("{bundle}.evil/Contents/Resources/main.js"),
                format!("{bundle}/main.js"),
                format!("{bundle}/Contents/../main.js"),
            ] {
                assert!(ScriptPath::resolve(&executable, &target).is_none());
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn app_named_directories_do_not_change_non_macos_paths() {
        let script = "/opt/Example.app/Contents/Resources/main.js";
        assert_eq!(
            ScriptPath::resolve("/opt/Example.app/Contents/MacOS/Electron", script),
            Some(script.to_owned())
        );
    }
}
