//! Debian-family root CA trust-store adapter.
//!
//! Ubuntu and Debian expose the same administrator-managed CA workflow: place
//! a PEM certificate with a `.crt` suffix in `/usr/local/share/ca-certificates`
//! and refresh the generated bundle with `update-ca-certificates`. The adapter
//! deliberately supports only the local-machine scope because that command
//! updates a system trust store, not a per-user store.

use std::{
    fs::{self, OpenOptions},
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    process::Command,
    str,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::{
    super::{CaError, CaResult, CertificateFingerprint, TrustStoreScope, TrustStoreStatus},
    TrustStoreAdapter,
};

const LOCAL_MACHINE_CA_DIRECTORY: &str = "/usr/local/share/ca-certificates";
const ROOT_CERTIFICATE_FILE_NAME: &str = "abyss-root-ca.crt";
const UPDATE_CA_CERTIFICATES_COMMAND: &str = "/usr/sbin/update-ca-certificates";

/// Ubuntu/Debian implementation of the Abyss root CA trust-store adapter.
pub(super) struct PlatformTrustStore;

impl TrustStoreAdapter for PlatformTrustStore {
    fn install_root_certificate(
        &self,
        certificate_der: &[u8],
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let certificate_path = certificate_path(scope)?;
        if certificate_path.exists() && !certificate_matches(&certificate_path, fingerprint)? {
            return Err(CaError::platform(
                "install Ubuntu/Debian root CA certificate",
                format!(
                    "refusing to replace a different certificate at {}",
                    certificate_path.display()
                ),
            ));
        }
        let certificate_pem = certificate_pem(certificate_der);
        write_certificate_atomically(&certificate_path, certificate_pem.as_bytes())?;
        update_system_certificates()?;
        self.root_certificate_status(fingerprint, scope)
    }

    fn uninstall_root_certificate(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let certificate_path = certificate_path(scope)?;
        if !certificate_matches(&certificate_path, fingerprint)? {
            return self.root_certificate_status(fingerprint, scope);
        }

        // Re-check the fingerprint immediately before removal so a concurrently
        // replaced file cannot cause the adapter to delete an unrelated CA.
        if certificate_matches(&certificate_path, fingerprint)? {
            fs::remove_file(&certificate_path).map_err(|source| {
                CaError::io(
                    "remove Ubuntu/Debian root CA certificate",
                    &certificate_path,
                    source,
                )
            })?;
            update_system_certificates()?;
        }
        self.root_certificate_status(fingerprint, scope)
    }

    fn root_certificate_status(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let certificate_path = certificate_path(scope)?;
        Ok(TrustStoreStatus {
            scope,
            installed: certificate_matches(&certificate_path, fingerprint)?,
            fingerprint_sha256: fingerprint.clone(),
        })
    }
}

fn certificate_path(scope: TrustStoreScope) -> CaResult<PathBuf> {
    match scope {
        TrustStoreScope::LocalMachine => {
            Ok(Path::new(LOCAL_MACHINE_CA_DIRECTORY).join(ROOT_CERTIFICATE_FILE_NAME))
        }
        TrustStoreScope::CurrentUser => Err(CaError::unsupported_platform(
            "linux",
            "current-user root certificate trust",
        )),
    }
}

fn certificate_matches(
    certificate_path: &Path,
    fingerprint: &CertificateFingerprint,
) -> CaResult<bool> {
    let certificate_pem = match fs::read(certificate_path) {
        Ok(certificate_pem) => certificate_pem,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(source) => {
            return Err(CaError::io(
                "read Ubuntu/Debian root CA certificate",
                certificate_path,
                source,
            ));
        }
    };
    let certificate_der = decode_certificate_pem(&certificate_pem).map_err(|details| {
        CaError::platform(
            "inspect Ubuntu/Debian root CA certificate",
            format!("{}: {details}", certificate_path.display()),
        )
    })?;
    Ok(CertificateFingerprint::from_der(&certificate_der) == fingerprint.clone())
}

fn write_certificate_atomically(certificate_path: &Path, contents: &[u8]) -> CaResult<()> {
    let parent = certificate_path.parent().ok_or_else(|| {
        CaError::platform(
            "install Ubuntu/Debian root CA certificate",
            "certificate path has no parent directory",
        )
    })?;
    let temporary_path = parent.join(format!(
        ".{}.tmp-{}",
        ROOT_CERTIFICATE_FILE_NAME,
        std::process::id()
    ));
    let write_result = (|| {
        let mut file = OpenOptions::new();
        file.create_new(true).write(true).mode(0o644);
        let mut file = file.open(&temporary_path).map_err(|source| {
            CaError::io(
                "create temporary Ubuntu/Debian root CA certificate",
                &temporary_path,
                source,
            )
        })?;
        file.write_all(contents).map_err(|source| {
            CaError::io(
                "write temporary Ubuntu/Debian root CA certificate",
                &temporary_path,
                source,
            )
        })?;
        file.sync_all().map_err(|source| {
            CaError::io(
                "sync temporary Ubuntu/Debian root CA certificate",
                &temporary_path,
                source,
            )
        })?;
        fs::rename(&temporary_path, certificate_path).map_err(|source| {
            CaError::io(
                "replace Ubuntu/Debian root CA certificate",
                certificate_path,
                source,
            )
        })
    })();
    if write_result.is_err() {
        drop(fs::remove_file(&temporary_path));
    }
    write_result
}

fn update_system_certificates() -> CaResult<()> {
    let output = Command::new(UPDATE_CA_CERTIFICATES_COMMAND)
        .output()
        .map_err(|source| {
            CaError::io(
                "run Ubuntu/Debian update-ca-certificates",
                UPDATE_CA_CERTIFICATES_COMMAND,
                source,
            )
        })?;
    if output.status.success() {
        return Ok(());
    }

    Err(CaError::platform(
        "run Ubuntu/Debian update-ca-certificates",
        command_failure_details(output.status.code(), &output.stdout, &output.stderr),
    ))
}

fn command_failure_details(code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> String {
    let code = code.map_or_else(|| "signal".to_owned(), |code| code.to_string());
    let stdout = String::from_utf8_lossy(stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(stderr).trim().to_owned();
    format!("exit={code}, stdout={stdout:?}, stderr={stderr:?}")
}

fn certificate_pem(certificate_der: &[u8]) -> String {
    let encoded = STANDARD.encode(certificate_der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        // STANDARD only produces ASCII, so this conversion cannot fail.
        pem.push_str(str::from_utf8(chunk).expect("base64 output must be ASCII"));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

fn decode_certificate_pem(certificate_pem: &[u8]) -> Result<Vec<u8>, &'static str> {
    let certificate_pem =
        str::from_utf8(certificate_pem).map_err(|_| "certificate is not UTF-8")?;
    let body = certificate_pem
        .strip_prefix("-----BEGIN CERTIFICATE-----")
        .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----\n"))
        .or_else(|| {
            certificate_pem
                .strip_prefix("-----BEGIN CERTIFICATE-----")
                .and_then(|value| value.strip_suffix("-----END CERTIFICATE-----"))
        })
        .ok_or("certificate PEM delimiters are invalid")?;
    let encoded: String = body.lines().map(str::trim).collect();
    STANDARD
        .decode(encoded)
        .map_err(|_| "certificate PEM body is not valid base64")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{certificate_path, certificate_pem, decode_certificate_pem};
    use crate::ca::TrustStoreScope;

    #[test]
    fn certificate_pem_round_trips_der_bytes() {
        let der = b"test certificate DER bytes";
        let pem = certificate_pem(der);

        assert_eq!(decode_certificate_pem(pem.as_bytes()), Ok(der.to_vec()));
    }

    #[test]
    fn malformed_certificate_pem_is_rejected() {
        assert!(decode_certificate_pem(b"not a certificate").is_err());
    }

    #[test]
    fn local_machine_certificate_path_uses_debian_ca_directory() {
        assert_eq!(
            certificate_path(TrustStoreScope::LocalMachine)
                .expect("local-machine scope should be supported"),
            PathBuf::from("/usr/local/share/ca-certificates/abyss-root-ca.crt")
        );
    }

    #[test]
    fn current_user_scope_is_not_supported() {
        assert!(certificate_path(TrustStoreScope::CurrentUser).is_err());
    }
}
