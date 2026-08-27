//! macOS filesystem paths and support-log locations for `abyss-broker`.

use std::{env, ffi::OsString, path::PathBuf};

use super::{PlatformAdapter, PlatformSupportLogFile};

const ABYSS_APPLICATION_SUPPORT_ROOT: &str = "/Library/Application Support/Abyss";
const ABYSS_HOME_ENV: &str = "ABYSS_HOME";
const ABYSS_LAUNCHD_LOG_PATH: &str = "/Library/Logs/Abyss/abyss-broker.launchd.log";

/// macOS implementation selected by the platform adapter factory.
pub(super) struct MacOsPlatformAdapter;

impl PlatformAdapter for MacOsPlatformAdapter {
    fn abyss_home(&self) -> PathBuf {
        env::var_os(ABYSS_HOME_ENV).map_or_else(
            || PathBuf::from(ABYSS_APPLICATION_SUPPORT_ROOT),
            PathBuf::from,
        )
    }

    fn platform_support_log_files(&self) -> Vec<PlatformSupportLogFile> {
        vec![PlatformSupportLogFile {
            name: "abyss-broker.launchd.log",
            // launchd owns this destination through StandardOutPath and
            // StandardErrorPath in the installed plist. ABYSS_HOME remains an
            // internal override for isolated development and black-box runs.
            path: macos_launchd_log_path(env::var_os(ABYSS_HOME_ENV)),
        }]
    }
}

fn macos_launchd_log_path(configured_home: Option<OsString>) -> PathBuf {
    configured_home.map_or_else(
        || PathBuf::from(ABYSS_LAUNCHD_LOG_PATH),
        |home| {
            PathBuf::from(home)
                .join("logs")
                .join("abyss-broker.launchd.log")
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    use super::macos_launchd_log_path;

    #[test]
    fn launchd_support_log_uses_the_installed_plist_location() {
        assert_eq!(
            macos_launchd_log_path(None),
            PathBuf::from("/Library/Logs/Abyss/abyss-broker.launchd.log")
        );
    }

    #[test]
    fn launchd_support_log_honors_the_isolated_broker_home() {
        assert_eq!(
            macos_launchd_log_path(Some(OsString::from("/private/var/abyss-test"))),
            PathBuf::from("/private/var/abyss-test/logs/abyss-broker.launchd.log")
        );
    }
}
