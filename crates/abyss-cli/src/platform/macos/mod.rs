//! macOS user-state, trust-store, process-lifecycle, and shell integration.

mod broker;
mod ca;

use std::{
    fs, io,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
};

use abyss_mitm::{CaMaterialPersistence, CaStore, TrustStoreScope};

use self::broker::BrokerController;
use super::PlatformAdapter;
use crate::{broker::BrokerEndpoint, error::CliError, paths::CliPaths};

const ABYSS_HOME_ENV: &str = "ABYSS_HOME";

/// macOS implementation selected by the platform adapter factory.
pub(super) struct MacOsPlatformAdapter;

impl PlatformAdapter for MacOsPlatformAdapter {
    fn ca_material_persistence(&self) -> &dyn CaMaterialPersistence {
        self
    }

    fn state_root(&self) -> Result<PathBuf, CliError> {
        resolve_state_root(
            std::env::var_os(ABYSS_HOME_ENV).map(PathBuf::from),
            std::env::var_os("HOME").map(PathBuf::from),
        )
    }

    fn user_home(&self) -> Result<PathBuf, CliError> {
        resolve_user_home(std::env::var_os("HOME").map(PathBuf::from))
    }

    fn configure_file_creation(&self, options: &mut fs::OpenOptions, mode: u32) {
        options.mode(mode);
    }

    fn protect_private_path(&self, path: &Path, mode: u32) -> io::Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    fn install_ca_trust(&self, ca_dir: &Path) -> Result<(), CliError> {
        install_current_user_ca(ca_dir)
    }

    fn install_ca_at(&self, ca_dir: &Path) -> Result<(), CliError> {
        install_current_user_ca(ca_dir)
    }

    fn start_broker(
        &self,
        paths: &CliPaths,
        _user: Option<&str>,
        restart: bool,
    ) -> Result<BrokerEndpoint, CliError> {
        BrokerController::start(paths, restart)
    }

    fn stop_broker(&self, paths: &CliPaths, _user: Option<&str>) -> Result<(), CliError> {
        BrokerController::stop(paths)
    }

    fn proxy_environment(&self, proxy_url: &str) -> String {
        posix_proxy_environment(proxy_url)
    }

    fn proxy_environment_variables(&self, proxy_url: &str) -> Vec<(String, String)> {
        posix_proxy_environment_variables(proxy_url)
    }

    fn system_information(&self) -> String {
        format!(
            "platform=macos\nos={}\nkernel={}\nlaunchd={}\n",
            command_output("sw_vers", &["-productVersion"]),
            command_output("uname", &["-sr"]),
            command_output("launchctl", &["version"]),
        )
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    let Ok(output) = Command::new(program).args(args).output() else {
        return "unavailable".to_owned();
    };
    if !output.status.success() {
        return "unavailable".to_owned();
    }
    normalized_output(&output.stdout)
}

fn normalized_output(output: &[u8]) -> String {
    let value = String::from_utf8_lossy(output)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if value.is_empty() {
        "unavailable".to_owned()
    } else {
        value
    }
}

fn posix_proxy_environment(proxy_url: &str) -> String {
    let proxy_url = format!("'{}'", proxy_url.replace('\'', "'\\''"));
    format!(
        "export HTTP_PROXY={proxy_url}\nexport HTTPS_PROXY={proxy_url}\nexport http_proxy={proxy_url}\nexport https_proxy={proxy_url}\nexport NO_PROXY='127.0.0.1,localhost'\n"
    )
}

fn posix_proxy_environment_variables(proxy_url: &str) -> Vec<(String, String)> {
    vec![
        ("HTTP_PROXY".to_owned(), proxy_url.to_owned()),
        ("HTTPS_PROXY".to_owned(), proxy_url.to_owned()),
        ("http_proxy".to_owned(), proxy_url.to_owned()),
        ("https_proxy".to_owned(), proxy_url.to_owned()),
        ("NO_PROXY".to_owned(), "127.0.0.1,localhost".to_owned()),
    ]
}

fn install_current_user_ca(ca_dir: &Path) -> Result<(), CliError> {
    let ca = CaStore::at(ca_dir).load_required()?;
    ca.install(TrustStoreScope::CurrentUser)?;
    Ok(())
}

fn resolve_state_root(
    abyss_home: Option<PathBuf>,
    user_home: Option<PathBuf>,
) -> Result<PathBuf, CliError> {
    abyss_home
        .or_else(|| {
            user_home.map(|home| {
                home.join("Library")
                    .join("Application Support")
                    .join("Abyss")
                    .join("cli")
            })
        })
        .ok_or_else(|| CliError::InvalidConfiguration("HOME or ABYSS_HOME must be set".to_owned()))
}

fn resolve_user_home(home: Option<PathBuf>) -> Result<PathBuf, CliError> {
    home.ok_or_else(|| {
        CliError::InvalidConfiguration("HOME is required to configure Claude Code".to_owned())
    })
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{MacOsPlatformAdapter, normalized_output, resolve_state_root, resolve_user_home};
    use crate::platform::PlatformAdapter as _;

    #[test]
    fn private_file_policy_uses_posix_modes() {
        let path = std::env::temp_dir().join(format!(
            "abyss-cli-macos-private-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock should be valid")
                .as_nanos()
        ));
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        MacOsPlatformAdapter.configure_file_creation(&mut options, 0o600);
        let file = options.open(&path).expect("private file should be created");
        drop(file);
        assert_eq!(
            fs::metadata(&path)
                .expect("created private file metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        MacOsPlatformAdapter
            .protect_private_path(&path, 0o640)
            .expect("private file mode should be updated");
        assert_eq!(
            fs::metadata(&path)
                .expect("private file metadata should read")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        drop(fs::remove_file(path));
    }

    #[test]
    fn state_root_prefers_abyss_home() {
        let root = resolve_state_root(
            Some(PathBuf::from("/tmp/abyss-override")),
            Some(PathBuf::from("/Users/example")),
        )
        .expect("ABYSS_HOME should resolve");

        assert_eq!(root, PathBuf::from("/tmp/abyss-override"));
    }

    #[test]
    fn state_root_uses_macos_application_support() {
        let root = resolve_state_root(None, Some(PathBuf::from("/Users/example")))
            .expect("HOME should resolve");

        assert_eq!(
            root,
            PathBuf::from("/Users/example/Library/Application Support/Abyss/cli")
        );
    }

    #[test]
    fn missing_home_is_rejected() {
        assert!(resolve_state_root(None, None).is_err());
        assert!(resolve_user_home(None).is_err());
    }

    #[test]
    fn command_output_is_normalized_to_one_line() {
        assert_eq!(normalized_output(b"one\r\n two\tthree\n"), "one two three");
        assert_eq!(normalized_output(b"  \n"), "unavailable");
    }

    #[test]
    fn shell_quote_escapes_single_quotes() {
        let output = MacOsPlatformAdapter.proxy_environment("http://127.0.0.1:28999/o'hare");
        assert!(output.contains("HTTP_PROXY='http://127.0.0.1:28999/o'\\''hare'"));
    }

    #[test]
    fn proxy_environment_matches_posix_contract() {
        assert_eq!(
            MacOsPlatformAdapter.proxy_environment("http://127.0.0.1:28999"),
            "export HTTP_PROXY='http://127.0.0.1:28999'\n\
             export HTTPS_PROXY='http://127.0.0.1:28999'\n\
             export http_proxy='http://127.0.0.1:28999'\n\
             export https_proxy='http://127.0.0.1:28999'\n\
             export NO_PROXY='127.0.0.1,localhost'\n"
        );
    }
}
