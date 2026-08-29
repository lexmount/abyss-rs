//! Version-pinned installation of local backend and dashboard runtime artifacts.

use std::{
    ffi::OsString,
    fs,
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use super::config::{
    BACKEND_VERSION, DASHBOARD_PACKAGE, DASHBOARD_VERSION, LocalPaths, atomic_write,
    ensure_private_directory,
};
use crate::{error::CliError, filesystem};

const BACKEND_RELEASE_BASE_URL: &str =
    "https://github.com/lexmount/abyss-backend/releases/download";
const BACKEND_RELEASE_BASE_URL_ENV: &str = "ABYSS_LOCAL_BACKEND_RELEASE_BASE_URL";
const BACKEND_BIN_ENV: &str = "ABYSS_LOCAL_BACKEND_BIN";
const DASHBOARD_BIN_ENV: &str = "ABYSS_LOCAL_DASHBOARD_BIN";
const MAX_BACKEND_BYTES: usize = 128 * 1024 * 1024;
const MAX_CHECKSUM_BYTES: usize = 1024 * 1024;
const MINIMUM_NODE_MAJOR: u64 = 22;
const MINIMUM_NPM_MAJOR: u64 = 10;

pub(super) struct RuntimeArtifacts {
    pub(super) backend: PathBuf,
    pub(super) dashboard: DashboardArtifact,
}

pub(super) enum DashboardArtifact {
    Direct(PathBuf),
    NodeScript { node: OsString, script: PathBuf },
}

pub(super) struct ArtifactInstaller<'a> {
    paths: &'a LocalPaths,
    client: reqwest::blocking::Client,
}

#[derive(Deserialize)]
struct DashboardManifest {
    version: String,
}

impl<'a> ArtifactInstaller<'a> {
    pub(super) fn new(paths: &'a LocalPaths) -> Result<Self, CliError> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(120))
            .build()
            .map_err(CliError::LocalArtifactRequest)?;
        Ok(Self { paths, client })
    }

    pub(super) fn ensure(&self) -> Result<RuntimeArtifacts, CliError> {
        Ok(RuntimeArtifacts {
            backend: self.ensure_backend()?,
            dashboard: self.ensure_dashboard()?,
        })
    }

    fn ensure_backend(&self) -> Result<PathBuf, CliError> {
        if let Some(path) = std::env::var_os(BACKEND_BIN_ENV).map(PathBuf::from) {
            validate_executable(&path, "ABYSS_LOCAL_BACKEND_BIN")?;
            return Ok(path);
        }
        let target = backend_target()?;
        let asset_name = format!("abyss-backend-v{BACKEND_VERSION}-{target}");
        let directory = self.paths.backend_runtime_dir();
        ensure_private_directory(&directory)?;
        let binary = directory.join(&asset_name);
        let checksum_file = directory.join("sha256");
        if installed_backend_is_valid(&binary, &checksum_file)? {
            return Ok(binary);
        }

        let release_base = std::env::var(BACKEND_RELEASE_BASE_URL_ENV).map_or_else(
            |_| format!("{BACKEND_RELEASE_BASE_URL}/v{BACKEND_VERSION}"),
            |base| base.trim_end_matches('/').to_owned(),
        );
        validate_release_base_url(&release_base)?;
        let checksums = self.download(&format!("{release_base}/SHA256SUMS"), MAX_CHECKSUM_BYTES)?;
        let expected = checksum_for_asset(&checksums, &asset_name)?;
        let bytes = self.download(&format!("{release_base}/{asset_name}"), MAX_BACKEND_BYTES)?;
        let actual = hex::encode(Sha256::digest(&bytes));
        if actual != expected {
            return Err(CliError::LocalArtifact(format!(
                "downloaded {asset_name} has SHA-256 {actual}, expected {expected}"
            )));
        }
        atomic_write(&binary, &bytes, 0o700, "backend executable")?;
        atomic_write(
            &checksum_file,
            format!("{expected}\n").as_bytes(),
            0o600,
            "backend checksum",
        )?;
        validate_executable(&binary, "installed backend")?;
        Ok(binary)
    }

    fn ensure_dashboard(&self) -> Result<DashboardArtifact, CliError> {
        if let Some(path) = std::env::var_os(DASHBOARD_BIN_ENV).map(PathBuf::from) {
            validate_executable(&path, "ABYSS_LOCAL_DASHBOARD_BIN")?;
            return Ok(DashboardArtifact::Direct(path));
        }
        let node = require_command_version("node", MINIMUM_NODE_MAJOR)?;
        let _npm = require_command_version("npm", MINIMUM_NPM_MAJOR)?;
        let directory = self.paths.dashboard_runtime_dir();
        let script = dashboard_script(&directory);
        if installed_dashboard_is_valid(&directory)? {
            return Ok(DashboardArtifact::NodeScript { node, script });
        }

        let parent = directory.parent().ok_or_else(|| {
            CliError::InvalidConfiguration("dashboard runtime path has no parent".to_owned())
        })?;
        ensure_private_directory(parent)?;
        let temporary = parent.join(format!(".install-{}", std::process::id()));
        if temporary.exists() {
            fs::remove_dir_all(&temporary).map_err(|source| {
                CliError::filesystem(
                    "remove stale dashboard staging directory",
                    &temporary,
                    source,
                )
            })?;
        }
        ensure_private_directory(&temporary)?;
        let result = (|| {
            let output = Command::new("npm")
                .args([
                    "install",
                    "--prefix",
                    path_text(&temporary, "dashboard staging directory")?,
                    "--ignore-scripts",
                    "--no-audit",
                    "--no-fund",
                    "--package-lock=false",
                    "--save=false",
                    DASHBOARD_PACKAGE,
                ])
                .output()
                .map_err(|source| CliError::filesystem("run npm", "npm", source))?;
            if !output.status.success() {
                return Err(CliError::Command {
                    program: format!("npm install {DASHBOARD_PACKAGE}"),
                    status: output.status,
                    stderr: bounded_stderr(&output.stderr),
                });
            }
            if !installed_dashboard_is_valid(&temporary)? {
                return Err(CliError::LocalArtifact(format!(
                    "npm did not install the expected {DASHBOARD_PACKAGE} package"
                )));
            }
            if directory.exists() {
                fs::remove_dir_all(&directory).map_err(|source| {
                    CliError::filesystem("replace dashboard runtime", &directory, source)
                })?;
            }
            fs::rename(&temporary, &directory).map_err(|source| {
                CliError::filesystem("install dashboard runtime", &directory, source)
            })?;
            filesystem::protect(&directory, 0o700).map_err(|source| {
                CliError::filesystem("protect dashboard runtime", &directory, source)
            })?;
            Ok(())
        })();
        if result.is_err() {
            drop(fs::remove_dir_all(&temporary));
        }
        result?;
        Ok(DashboardArtifact::NodeScript { node, script })
    }

    fn download(&self, url: &str, maximum_bytes: usize) -> Result<Vec<u8>, CliError> {
        let response = self
            .client
            .get(url)
            .send()
            .map_err(CliError::LocalArtifactRequest)?;
        if !response.status().is_success() {
            return Err(CliError::LocalArtifact(format!(
                "download {url} returned HTTP {}",
                response.status()
            )));
        }
        let maximum_bytes_u64 = u64::try_from(maximum_bytes)
            .map_err(|_| CliError::LocalArtifact("artifact size limit is invalid".to_owned()))?;
        if response
            .content_length()
            .is_some_and(|length| length > maximum_bytes_u64)
        {
            return Err(CliError::LocalArtifact(format!(
                "download {url} exceeds the {maximum_bytes}-byte size limit"
            )));
        }
        let limit = maximum_bytes_u64.saturating_add(1);
        let mut bytes = Vec::new();
        response
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|source| {
                CliError::filesystem("read downloaded local artifact", url, source)
            })?;
        if bytes.len() > maximum_bytes {
            return Err(CliError::LocalArtifact(format!(
                "download {url} exceeds the {maximum_bytes}-byte size limit"
            )));
        }
        Ok(bytes)
    }
}

fn backend_target() -> Result<&'static str, CliError> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("macos", "aarch64") => Ok("aarch64-apple-darwin"),
        ("linux", "x86_64") => Ok("x86_64-unknown-linux-musl"),
        (os, architecture) => Err(CliError::InvalidConfiguration(format!(
            "local deployment supports macOS ARM64 and Linux x86_64; found {os}/{architecture}"
        ))),
    }
}

fn validate_release_base_url(value: &str) -> Result<(), CliError> {
    let parsed = reqwest::Url::parse(value).map_err(|error| {
        CliError::InvalidConfiguration(format!("invalid backend release URL: {error}"))
    })?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CliError::InvalidConfiguration(
            "backend release URL must be absolute HTTP(S) without credentials, query, or fragment"
                .to_owned(),
        ));
    }
    Ok(())
}

fn checksum_for_asset(contents: &[u8], asset_name: &str) -> Result<String, CliError> {
    let text = std::str::from_utf8(contents)
        .map_err(|_| CliError::LocalArtifact("SHA256SUMS is not UTF-8".to_owned()))?;
    let mut found = None;
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let Some(checksum) = fields.next() else {
            continue;
        };
        let Some(file_name) = fields.next() else {
            continue;
        };
        if file_name.trim_start_matches('*') != asset_name {
            continue;
        }
        if found.is_some() {
            return Err(CliError::LocalArtifact(format!(
                "SHA256SUMS contains duplicate entries for {asset_name}"
            )));
        }
        if checksum.len() != 64 || !checksum.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CliError::LocalArtifact(format!(
                "SHA256SUMS contains an invalid checksum for {asset_name}"
            )));
        }
        found = Some(checksum.to_ascii_lowercase());
    }
    found
        .ok_or_else(|| CliError::LocalArtifact(format!("SHA256SUMS does not contain {asset_name}")))
}

fn installed_backend_is_valid(binary: &Path, checksum_file: &Path) -> Result<bool, CliError> {
    if !binary.is_file() || !checksum_file.is_file() {
        return Ok(false);
    }
    let expected = fs::read_to_string(checksum_file).map_err(|source| {
        CliError::filesystem("read installed backend checksum", checksum_file, source)
    })?;
    let expected = expected.trim();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(false);
    }
    let mut file = fs::File::open(binary)
        .map_err(|source| CliError::filesystem("open installed backend", binary, source))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|source| CliError::filesystem("hash installed backend", binary, source))?;
        if count == 0 {
            break;
        }
        digest
            .write_all(&buffer[..count])
            .map_err(|source| CliError::filesystem("hash installed backend", binary, source))?;
    }
    Ok(hex::encode(digest.finalize()) == expected.to_ascii_lowercase())
}

fn installed_dashboard_is_valid(directory: &Path) -> Result<bool, CliError> {
    let manifest = directory
        .join("node_modules")
        .join("@lexmount.com")
        .join("abyss-dashboard")
        .join("package.json");
    let script = dashboard_script(directory);
    if !manifest.is_file() || !script.is_file() {
        return Ok(false);
    }
    let contents = fs::read(&manifest).map_err(|source| {
        CliError::filesystem("read dashboard package manifest", &manifest, source)
    })?;
    let Ok(manifest) = serde_json::from_slice::<DashboardManifest>(&contents) else {
        return Ok(false);
    };
    Ok(manifest.version == DASHBOARD_VERSION)
}

fn dashboard_script(directory: &Path) -> PathBuf {
    directory
        .join("node_modules")
        .join("@lexmount.com")
        .join("abyss-dashboard")
        .join("bin")
        .join("abyss-dashboard.mjs")
}

fn require_command_version(program: &str, minimum_major: u64) -> Result<OsString, CliError> {
    let output = Command::new(program)
        .arg("--version")
        .output()
        .map_err(|source| {
            CliError::filesystem("run local deployment dependency", program, source)
        })?;
    if !output.status.success() {
        return Err(CliError::Command {
            program: format!("{program} --version"),
            status: output.status,
            stderr: bounded_stderr(&output.stderr),
        });
    }
    let version = String::from_utf8_lossy(&output.stdout);
    let major = version
        .trim()
        .trim_start_matches('v')
        .split('.')
        .next()
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            CliError::InvalidConfiguration(format!(
                "could not determine {program} major version from `{}`",
                version.trim()
            ))
        })?;
    if major < minimum_major {
        return Err(CliError::InvalidConfiguration(format!(
            "{program} {minimum_major} or newer is required for the local dashboard; found {}",
            version.trim()
        )));
    }
    Ok(OsString::from(program))
}

fn validate_executable(path: &Path, label: &str) -> Result<(), CliError> {
    let metadata = fs::metadata(path)
        .map_err(|source| CliError::filesystem("inspect local executable", path, source))?;
    if !metadata.is_file() {
        return Err(CliError::InvalidConfiguration(format!(
            "{label} is not a regular file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(CliError::InvalidConfiguration(format!(
                "{label} is not executable: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str, CliError> {
    path.to_str().ok_or_else(|| {
        CliError::InvalidConfiguration(format!("{label} is not valid UTF-8: {}", path.display()))
    })
}

fn bounded_stderr(stderr: &[u8]) -> String {
    const MAXIMUM: usize = 8 * 1024;
    let start = stderr.len().saturating_sub(MAXIMUM);
    String::from_utf8_lossy(&stderr[start..]).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use sha2::{Digest as _, Sha256};

    use super::{checksum_for_asset, validate_release_base_url};

    #[test]
    fn checksum_parser_requires_one_exact_asset() {
        let digest = hex::encode(Sha256::digest(b"backend"));
        let checksums = format!("{digest}  abyss-backend-v1.0.0-aarch64-apple-darwin\n");

        assert_eq!(
            checksum_for_asset(
                checksums.as_bytes(),
                "abyss-backend-v1.0.0-aarch64-apple-darwin"
            )
            .expect("checksum should resolve"),
            digest
        );
        assert!(checksum_for_asset(checksums.as_bytes(), "other").is_err());
    }

    #[test]
    fn release_base_rejects_credentials_and_non_http_schemes() {
        assert!(validate_release_base_url("https://github.com/example/release").is_ok());
        assert!(validate_release_base_url("https://user@example.test/release").is_err());
        assert!(validate_release_base_url("file:///tmp/release").is_err());
    }
}
