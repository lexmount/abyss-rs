//! macOS root CA trust-store adapter.
//!
//! The adapter uses the platform `security` command as the stable Keychain
//! boundary. It stores only public root certificate material, matches by
//! SHA-256 fingerprint, and removes only the exact Abyss certificate.

use super::{
    super::{CaError, CaResult, CertificateFingerprint, TrustStoreScope, TrustStoreStatus},
    TrustStoreAdapter,
};
use std::{
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const SECURITY_COMMAND: &str = "/usr/bin/security";
const LOGIN_KEYCHAIN_FILE: &str = "login.keychain-db";
const LEGACY_LOGIN_KEYCHAIN_FILE: &str = "login.keychain";
const SYSTEM_KEYCHAIN_PATH: &str = "/Library/Keychains/System.keychain";
const SHA256_HASH_PREFIX: &str = "SHA-256 hash";

/// macOS implementation of the Abyss root CA trust-store adapter.
pub(super) struct PlatformTrustStore;

impl TrustStoreAdapter for PlatformTrustStore {
    fn install_root_certificate(
        &self,
        certificate_der: &[u8],
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let keychain = KeychainTarget::for_scope(scope)?;
        let certificate_file = TemporaryCertificateFile::write(certificate_der)?;
        let args = add_trusted_cert_args(&keychain, certificate_file.path());
        run_security("macOS add trusted root certificate", &args)?;
        self.root_certificate_status(fingerprint, scope)
    }

    fn uninstall_root_certificate(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let keychain = KeychainTarget::for_scope(scope)?;
        if self.root_certificate_status(fingerprint, scope)?.installed {
            let args = delete_certificate_args(fingerprint, &keychain);
            if let Err(delete_error) = run_security("macOS delete trusted root certificate", &args)
            {
                let status_after_failed_delete = self.root_certificate_status(fingerprint, scope);
                if matches!(&status_after_failed_delete, Ok(status) if !status.installed) {
                    return status_after_failed_delete;
                }
                return Err(delete_error);
            }
        }
        self.root_certificate_status(fingerprint, scope)
    }

    fn root_certificate_status(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let keychain = KeychainTarget::for_scope(scope)?;
        let args = find_certificate_args(&keychain);
        let output = run_security("macOS find trusted root certificate", &args)?;
        Ok(TrustStoreStatus {
            scope,
            installed: output_contains_fingerprint(&output, fingerprint),
            fingerprint_sha256: fingerprint.clone(),
        })
    }
}

#[derive(Debug, Clone)]
struct KeychainTarget {
    /// Concrete keychain file passed to the `security` command.
    path: PathBuf,
    /// Whether `security add-trusted-cert` should write admin trust settings.
    admin_domain: bool,
}

impl KeychainTarget {
    /// Resolves the product-level trust scope to a concrete macOS keychain.
    fn for_scope(scope: TrustStoreScope) -> CaResult<Self> {
        match scope {
            TrustStoreScope::CurrentUser => {
                let home = env::var_os("HOME").ok_or_else(|| {
                    CaError::platform("macOS current-user keychain", "HOME is not set")
                })?;
                Ok(Self::current_user_from_home(Path::new(&home)))
            }
            TrustStoreScope::LocalMachine => Ok(Self::local_machine()),
        }
    }

    fn current_user_from_home(home: &Path) -> Self {
        let keychain_dir = home.join("Library").join("Keychains");
        let modern = keychain_dir.join(LOGIN_KEYCHAIN_FILE);
        let legacy = keychain_dir.join(LEGACY_LOGIN_KEYCHAIN_FILE);
        Self {
            // Modern macOS uses login.keychain-db. Older systems may still have
            // login.keychain, so only fall back when that file actually exists.
            path: if modern.exists() || !legacy.exists() {
                modern
            } else {
                legacy
            },
            admin_domain: false,
        }
    }

    fn local_machine() -> Self {
        Self {
            path: PathBuf::from(SYSTEM_KEYCHAIN_PATH),
            admin_domain: true,
        }
    }
}

struct TemporaryCertificateFile {
    /// DER certificate file path consumed by `security add-trusted-cert`.
    path: PathBuf,
}

impl TemporaryCertificateFile {
    /// Writes public certificate DER to a temporary file for the `security` CLI.
    ///
    /// The private key never goes through this path. macOS trust installation
    /// needs only the root certificate public material.
    fn write(certificate_der: &[u8]) -> CaResult<Self> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0_u128, |duration| duration.as_nanos());
        let path = env::temp_dir().join(format!(
            "abyss-macos-root-ca-{}-{timestamp}.der",
            std::process::id()
        ));
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(|source| CaError::io("create temporary root CA DER", &path, source))?;
        file.write_all(certificate_der)
            .map_err(|source| CaError::io("write temporary root CA DER", &path, source))?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryCertificateFile {
    fn drop(&mut self) {
        // Best effort cleanup. A failure here should not mask the Keychain
        // operation result that the caller already received.
        if fs::remove_file(&self.path).is_err() {}
    }
}

fn add_trusted_cert_args(keychain: &KeychainTarget, certificate_path: &Path) -> Vec<OsString> {
    let mut args = vec![OsString::from("add-trusted-cert")];
    if keychain.admin_domain {
        args.push(OsString::from("-d"));
    }
    args.extend([
        OsString::from("-r"),
        OsString::from("trustRoot"),
        OsString::from("-k"),
    ]);
    args.push(keychain.path.as_os_str().to_owned());
    args.push(certificate_path.as_os_str().to_owned());
    args
}

fn delete_certificate_args(
    fingerprint: &CertificateFingerprint,
    keychain: &KeychainTarget,
) -> Vec<OsString> {
    // `-Z` keeps removal constrained to the exact root certificate fingerprint.
    // `-t` also removes user trust settings attached to that certificate.
    vec![
        OsString::from("delete-certificate"),
        OsString::from("-Z"),
        OsString::from(fingerprint.to_hex().to_ascii_uppercase()),
        OsString::from("-t"),
        keychain.path.as_os_str().to_owned(),
    ]
}

fn find_certificate_args(keychain: &KeychainTarget) -> Vec<OsString> {
    vec![
        OsString::from("find-certificate"),
        OsString::from("-a"),
        OsString::from("-Z"),
        keychain.path.as_os_str().to_owned(),
    ]
}

fn run_security(operation: &'static str, args: &[OsString]) -> CaResult<Output> {
    // Keep the platform boundary at the `security` command instead of binding
    // Keychain FFI here. This preserves the same behavior administrators use
    // manually and keeps unsafe macOS interop out of the MITM crate.
    let output = Command::new(SECURITY_COMMAND)
        .args(args.iter().map(OsString::as_os_str))
        .output()
        .map_err(|source| CaError::io(operation, SECURITY_COMMAND, source))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(CaError::platform(
            operation,
            command_failure_details(output.status.code(), &output.stdout, &output.stderr),
        ))
    }
}

fn command_failure_details(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    let code = code.map_or_else(
        || "terminated by signal".to_owned(),
        |value| value.to_string(),
    );
    let stdout = String::from_utf8_lossy(stdout);
    let stderr = String::from_utf8_lossy(stderr);
    format!(
        "security exited with status {code}; stdout: {}; stderr: {}",
        stdout.trim(),
        stderr.trim()
    )
}

fn output_contains_fingerprint(output: &Output, fingerprint: &CertificateFingerprint) -> bool {
    let expected = fingerprint.to_hex();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Different macOS versions have emitted `security` diagnostics on either
    // stream, so status parsing intentionally checks both.
    stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(parse_sha256_hash_line)
        .any(|hash| hash == expected)
}

fn parse_sha256_hash_line(line: &str) -> Option<String> {
    let (prefix, value) = line.split_once(':')?;
    if !prefix.trim().eq_ignore_ascii_case(SHA256_HASH_PREFIX) {
        return None;
    }
    let normalized = normalize_hex(value);
    (normalized.len() == 64).then_some(normalized)
}

fn normalize_hex(value: &str) -> String {
    value
        .chars()
        .filter(char::is_ascii_hexdigit)
        .flat_map(char::to_lowercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        ffi::OsString,
        fs,
        os::unix::{fs::PermissionsExt as _, process::ExitStatusExt as _},
        path::{Path, PathBuf},
        process::{ExitStatus, Output},
    };

    use super::{
        CertificateFingerprint, KeychainTarget, TemporaryCertificateFile, add_trusted_cert_args,
        command_failure_details, delete_certificate_args, output_contains_fingerprint,
        parse_sha256_hash_line,
    };

    #[test]
    fn current_user_keychain_defaults_to_modern_login_keychain() {
        let target = KeychainTarget::current_user_from_home(Path::new("/Users/example"));

        assert_eq!(
            target.path,
            PathBuf::from("/Users/example/Library/Keychains/login.keychain-db")
        );
        assert!(!target.admin_domain);
    }

    #[test]
    fn local_machine_keychain_uses_system_store_and_admin_domain() {
        let target = KeychainTarget::local_machine();

        assert_eq!(
            target.path,
            PathBuf::from("/Library/Keychains/System.keychain")
        );
        assert!(target.admin_domain);
    }

    #[test]
    fn local_machine_install_args_include_admin_domain() {
        let keychain = KeychainTarget::local_machine();
        let args = add_trusted_cert_args(&keychain, Path::new("/tmp/root.der"));

        assert_eq!(
            args,
            vec![
                OsString::from("add-trusted-cert"),
                OsString::from("-d"),
                OsString::from("-r"),
                OsString::from("trustRoot"),
                OsString::from("-k"),
                OsString::from("/Library/Keychains/System.keychain"),
                OsString::from("/tmp/root.der"),
            ]
        );
    }

    #[test]
    fn delete_args_match_by_uppercase_fingerprint_and_trust_settings() {
        let fingerprint = CertificateFingerprint::from_der(b"root certificate");
        let keychain = KeychainTarget::local_machine();
        let args = delete_certificate_args(&fingerprint, &keychain);

        assert_eq!(args[0], OsString::from("delete-certificate"));
        assert_eq!(args[1], OsString::from("-Z"));
        assert_eq!(
            args[2],
            OsString::from(fingerprint.to_hex().to_ascii_uppercase())
        );
        assert_eq!(args[3], OsString::from("-t"));
    }

    #[test]
    fn temporary_certificate_file_is_owner_only() {
        let certificate_file = TemporaryCertificateFile::write(b"root certificate")
            .expect("temporary certificate file should be created");

        let mode = fs::metadata(certificate_file.path())
            .expect("temporary certificate file should exist")
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(mode, 0o600);
    }

    #[test]
    fn parses_security_sha256_hash_lines() {
        let hash = "C853E5F13F4C7B52D500ACB89068E8DA5D9E0C06F891D3BE52CC34803C1E2D96";

        let parsed = parse_sha256_hash_line(&format!("SHA-256 hash: {hash}"))
            .expect("SHA-256 hash line should parse");

        assert_eq!(parsed, hash.to_ascii_lowercase());
    }

    #[test]
    fn ignores_sha1_hash_lines() {
        assert_eq!(
            parse_sha256_hash_line("SHA-1 hash: 4F2A98758EF058D2C7082C7F0E56B7372123BE81"),
            None
        );
    }

    #[test]
    fn detects_fingerprint_in_security_output() {
        let fingerprint = CertificateFingerprint::from_der(b"root certificate");
        let output = Output {
            status: ExitStatus::from_raw(0),
            stdout: format!(
                "SHA-256 hash: {}\n",
                fingerprint.to_hex().to_ascii_uppercase()
            )
            .into_bytes(),
            stderr: Vec::new(),
        };

        assert!(output_contains_fingerprint(&output, &fingerprint));
    }

    #[test]
    fn command_failure_details_include_status_and_stderr() {
        let details = command_failure_details(Some(44_i32), b"", b"certificate not found\n");

        assert!(details.contains("44"));
        assert!(details.contains("certificate not found"));
    }
}
