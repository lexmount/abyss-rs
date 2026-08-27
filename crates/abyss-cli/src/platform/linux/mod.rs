//! Linux service, privilege, trust-store, and shell integration.

use std::{
    fs, io,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    process::Command,
};

use abyss_mitm::{CaMaterialPersistence, CaStore, TrustStoreScope};

use super::PlatformAdapter;
use crate::{broker::BrokerEndpoint, error::CliError, paths::CliPaths};

mod broker;
mod ca;

const ABYSS_HOME_ENV: &str = "ABYSS_HOME";

/// Linux implementation selected by the platform adapter factory.
pub(super) struct LinuxPlatformAdapter;

impl PlatformAdapter for LinuxPlatformAdapter {
    fn ca_material_persistence(&self) -> &dyn CaMaterialPersistence {
        self
    }

    fn state_root(&self) -> Result<PathBuf, CliError> {
        std::env::var_os(ABYSS_HOME_ENV)
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".abyss")))
            .ok_or_else(|| {
                CliError::InvalidConfiguration("HOME or ABYSS_HOME must be set".to_owned())
            })
    }

    fn user_home(&self) -> Result<PathBuf, CliError> {
        std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| {
            CliError::InvalidConfiguration("HOME is required to configure Claude Code".to_owned())
        })
    }

    fn configure_file_creation(&self, options: &mut fs::OpenOptions, mode: u32) {
        options.mode(mode);
    }

    fn protect_private_path(&self, path: &Path, mode: u32) -> io::Result<()> {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
    }

    fn install_ca_trust(&self, ca_dir: &Path) -> Result<(), CliError> {
        let executable = std::env::current_exe()
            .map_err(|source| CliError::filesystem("resolve abyss executable", "abyss", source))?;
        let ca_dir = ca_dir.to_str().ok_or_else(|| {
            CliError::InvalidConfiguration("CA directory is not valid UTF-8".to_owned())
        })?;
        run_privileged(&executable, &["internal", "ca-install", "--ca-dir", ca_dir])
    }

    fn install_ca_at(&self, ca_dir: &Path) -> Result<(), CliError> {
        let ca = CaStore::at(ca_dir).load_required()?;
        ca.install(TrustStoreScope::LocalMachine)?;
        Ok(())
    }

    fn start_broker(
        &self,
        paths: &CliPaths,
        user: Option<&str>,
        restart: bool,
    ) -> Result<BrokerEndpoint, CliError> {
        broker::BrokerController::start(paths, user, restart)
    }

    fn stop_broker(&self, paths: &CliPaths, user: Option<&str>) -> Result<(), CliError> {
        broker::BrokerController::stop(paths, user)
    }

    fn proxy_environment(&self, proxy_url: &str) -> String {
        proxy_environment(proxy_url)
    }

    fn proxy_environment_variables(&self, proxy_url: &str) -> Vec<(String, String)> {
        proxy_environment_variables(proxy_url)
    }

    fn system_information(&self) -> String {
        format!(
            "platform=linux\nos={}\ndistribution={}\nsystemd={}\n",
            command_output("uname", &["-sr"]),
            distribution(),
            command_output("systemctl", &["--version"]),
        )
    }
}

fn distribution() -> String {
    let Ok(content) = fs::read_to_string("/etc/os-release") else {
        return "unknown".to_owned();
    };
    let mut id = None;
    let mut version = None;
    for line in content.lines() {
        if let Some(value) = line.strip_prefix("ID=") {
            id = Some(value.trim_matches('"').to_owned());
        } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version = Some(value.trim_matches('"').to_owned());
        }
    }
    match (id, version) {
        (Some(id), Some(version)) => format!("{id} {version}"),
        (Some(id), None) => id,
        _ => "unknown".to_owned(),
    }
}

fn command_output(program: &str, args: &[&str]) -> String {
    let Ok(output) = Command::new(program).args(args).output() else {
        return "unavailable".to_owned();
    };
    if !output.status.success() {
        return "unavailable".to_owned();
    }
    let value = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if value.is_empty() {
        "unavailable".to_owned()
    } else {
        value
    }
}

fn proxy_environment(proxy_url: &str) -> String {
    let proxy_url = format!("'{}'", proxy_url.replace('\'', "'\\''"));
    format!(
        "export HTTP_PROXY={proxy_url}\nexport HTTPS_PROXY={proxy_url}\nexport http_proxy={proxy_url}\nexport https_proxy={proxy_url}\nexport NO_PROXY='127.0.0.1,localhost'\n"
    )
}

fn proxy_environment_variables(proxy_url: &str) -> Vec<(String, String)> {
    vec![
        ("HTTP_PROXY".to_owned(), proxy_url.to_owned()),
        ("HTTPS_PROXY".to_owned(), proxy_url.to_owned()),
        ("http_proxy".to_owned(), proxy_url.to_owned()),
        ("https_proxy".to_owned(), proxy_url.to_owned()),
        ("NO_PROXY".to_owned(), "127.0.0.1,localhost".to_owned()),
    ]
}

fn run_privileged(program: &Path, args: &[&str]) -> Result<(), CliError> {
    let mut command = privileged_command(program.to_string_lossy().as_ref(), args.iter().copied());
    let output = command
        .output()
        .map_err(|source| CliError::filesystem("run privileged command", program, source))?;
    if output.status.success() {
        return Ok(());
    }
    Err(CliError::Command {
        program: format!("sudo {}", program.display()),
        status: output.status,
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

fn privileged_command<'a, I>(program: &str, args: I) -> Command
where
    I: IntoIterator<Item = &'a str>,
{
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .is_ok_and(|output| output.status.success() && output.stdout == b"0\n");
    let mut command = if is_root {
        Command::new(program)
    } else {
        let mut sudo = Command::new("sudo");
        sudo.arg(program);
        sudo
    };
    command.args(args);
    command
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::PermissionsExt as _,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::LinuxPlatformAdapter;
    use crate::platform::PlatformAdapter as _;

    #[test]
    fn private_file_policy_uses_posix_modes() {
        let path = std::env::temp_dir().join(format!(
            "abyss-cli-linux-private-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock should be valid")
                .as_nanos()
        ));
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        LinuxPlatformAdapter.configure_file_creation(&mut options, 0o600);
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

        LinuxPlatformAdapter
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
    fn environment_uses_explicit_proxy_for_http_and_https() {
        let output = LinuxPlatformAdapter.proxy_environment("http://127.0.0.1:28999");

        assert!(output.contains("HTTP_PROXY='http://127.0.0.1:28999'"));
        assert!(output.contains("HTTPS_PROXY='http://127.0.0.1:28999'"));
        assert!(output.contains("NO_PROXY='127.0.0.1,localhost'"));
    }

    #[test]
    fn shell_quotes_proxy_url() {
        let output = LinuxPlatformAdapter.proxy_environment("http://127.0.0.1:28999/o'hare");
        assert!(output.contains("HTTP_PROXY='http://127.0.0.1:28999/o'\\''hare'"));
    }
}
