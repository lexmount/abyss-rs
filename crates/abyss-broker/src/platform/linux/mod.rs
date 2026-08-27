//! Linux filesystem paths for `abyss-broker`.

use std::{env, ffi::OsString, path::PathBuf};

use super::{PlatformAdapter, PlatformSupportLogFile};

const ABYSS_HOME_ENV: &str = "ABYSS_HOME";

/// Linux implementation selected by the platform adapter factory.
pub(super) struct LinuxPlatformAdapter;

impl PlatformAdapter for LinuxPlatformAdapter {
    fn abyss_home(&self) -> PathBuf {
        linux_abyss_home(env::var_os(ABYSS_HOME_ENV), env::var_os("HOME"))
    }

    fn platform_support_log_files(&self) -> Vec<PlatformSupportLogFile> {
        Vec::new()
    }
}

fn linux_abyss_home(configured_home: Option<OsString>, home: Option<OsString>) -> PathBuf {
    configured_home.map_or_else(
        || {
            home.map_or_else(
                || env::temp_dir().join("abyss"),
                |home| PathBuf::from(home).join(".abyss"),
            )
        },
        PathBuf::from,
    )
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    use super::linux_abyss_home;

    #[test]
    fn configured_root_takes_precedence_over_home() {
        assert_eq!(
            linux_abyss_home(
                Some(OsString::from("/srv/abyss-test")),
                Some(OsString::from("/home/tester")),
            ),
            PathBuf::from("/srv/abyss-test")
        );
    }

    #[test]
    fn linux_defaults_to_hidden_home_directory() {
        assert_eq!(
            linux_abyss_home(None, Some(OsString::from("/home/tester"))),
            PathBuf::from("/home/tester/.abyss")
        );
    }
}
