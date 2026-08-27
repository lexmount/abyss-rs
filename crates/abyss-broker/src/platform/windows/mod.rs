//! Windows filesystem paths for `abyss-broker`.

use std::{env, ffi::OsString, path::PathBuf};

use super::PlatformAdapter;

const ABYSS_HOME_ENV: &str = "ABYSS_HOME";

/// Windows implementation selected by the platform adapter factory.
pub(super) struct WindowsPlatformAdapter;

impl PlatformAdapter for WindowsPlatformAdapter {
    fn abyss_home(&self) -> PathBuf {
        windows_abyss_home(env::var_os(ABYSS_HOME_ENV), env::var_os("ProgramData"))
    }
}

fn windows_abyss_home(
    configured_home: Option<OsString>,
    program_data: Option<OsString>,
) -> PathBuf {
    configured_home.map_or_else(
        || {
            program_data
                .map_or_else(env::temp_dir, PathBuf::from)
                .join("Abyss")
        },
        PathBuf::from,
    )
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf};

    use super::windows_abyss_home;

    #[test]
    fn configured_root_takes_precedence_over_program_data() {
        assert_eq!(
            windows_abyss_home(
                Some(OsString::from(r"C:\Users\tester\AppData\Local\Abyss\cli")),
                Some(OsString::from(r"C:\ProgramData")),
            ),
            PathBuf::from(r"C:\Users\tester\AppData\Local\Abyss\cli")
        );
    }

    #[test]
    fn host_default_remains_program_data() {
        assert_eq!(
            windows_abyss_home(None, Some(OsString::from(r"C:\ProgramData"))),
            PathBuf::from(r"C:\ProgramData\Abyss")
        );
    }
}
