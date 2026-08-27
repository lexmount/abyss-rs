//! Root CA lifecycle and trust-store operations for Abyss MITM.
//!
//! This module owns the product-level CA boundary: it loads or generates local
//! CA material, exposes status/export data, and delegates OS trust installation
//! to platform adapters under [`platform`]. Brokers and platform wrappers should
//! pass an explicit CA directory to these safe APIs instead of generating or
//! installing certificates themselves.

mod platform;

use std::{
    fmt, fs, io,
    path::{Path, PathBuf},
};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde::{Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

const ROOT_CERT_DER_FILE_NAME: &str = "abyss-root-ca.der";
const ROOT_CERT_PEM_FILE_NAME: &str = "abyss-root-ca.pem";
const ROOT_KEY_PEM_FILE_NAME: &str = "abyss-root-ca-key.pem";

/// Result alias for CA lifecycle and trust-store work.
pub type CaResult<T> = Result<T, CaError>;

/// Persistence boundary for generated CA material.
///
/// The MITM crate owns the CA file layout and generation sequence, while the
/// executable that owns a store supplies its platform-specific access policy.
/// Implementations must secure the store before the private key is read or
/// written and must durably flush each completed write before returning.
pub trait CaMaterialPersistence {
    /// Prepares the store directory and protects an existing private key.
    ///
    /// `private_key` may not exist yet. Implementations must still prepare
    /// `directory` so a subsequently created key is never exposed through an
    /// inherited permissive directory policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be created or protected.
    fn prepare_store(&self, directory: &Path, private_key: &Path) -> io::Result<()>;

    /// Writes public certificate material using the owner's platform policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the public material cannot be written and synced.
    fn write_public(&self, path: &Path, contents: &[u8]) -> io::Result<()>;

    /// Writes the CA signing key using the owner's private-file policy.
    ///
    /// # Errors
    ///
    /// Returns an error when the private key cannot be written and synced.
    fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()>;
}

/// Errors returned by CA material and platform trust-store operations.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CaError {
    /// File-system operation failed while reading or writing CA material.
    #[error("CA I/O error during {operation} at {path}: {source}")]
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Path involved in the failed operation.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Existing CA directory contains only part of the required material.
    #[error("invalid CA store at {directory}: {details}")]
    InvalidStore {
        /// CA store directory.
        directory: PathBuf,
        /// Human-readable validation failure.
        details: String,
    },
    /// Required CA material was not found in the explicit CA directory.
    #[error(
        "missing CA store at {directory}: expected abyss-root-ca.der, abyss-root-ca.pem, and abyss-root-ca-key.pem"
    )]
    MissingStore {
        /// CA store directory.
        directory: PathBuf,
    },
    /// CA material could not be generated.
    #[error("failed to generate CA material during {operation}: {source}")]
    Generation {
        /// Operation being performed.
        operation: &'static str,
        /// Source certificate generation error.
        #[source]
        source: rcgen::Error,
    },
    /// Current platform adapter does not support the requested operation yet.
    #[error("CA trust-store operation {operation} is not supported on {platform}")]
    UnsupportedPlatform {
        /// Platform adapter name.
        platform: &'static str,
        /// Operation being performed.
        operation: &'static str,
    },
    /// Platform trust-store operation failed.
    #[error("CA trust-store operation {operation} failed: {details}")]
    Platform {
        /// Operation being performed.
        operation: &'static str,
        /// Platform-specific failure details.
        details: String,
    },
}

impl CaError {
    pub(crate) fn io(operation: &'static str, path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io {
            operation,
            path: path.into(),
            source,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn unsupported_platform(
        platform: &'static str,
        operation: &'static str,
    ) -> Self {
        Self::UnsupportedPlatform {
            platform,
            operation,
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn platform(operation: &'static str, details: impl Into<String>) -> Self {
        Self::Platform {
            operation,
            details: details.into(),
        }
    }
}

/// Filesystem location for Abyss root CA material.
#[derive(Debug, Clone)]
pub struct CaStore {
    directory: PathBuf,
}

/// Local root CA material loaded from a [`CaStore`].
#[derive(Debug, Clone)]
pub struct CertificateAuthority {
    certificate_der: Box<[u8]>,
    certificate_pem: String,
    private_key_pem: String,
    fingerprint_sha256: CertificateFingerprint,
}

/// SHA-256 fingerprint over the DER-encoded root certificate.
#[derive(Clone, Hash, PartialEq)]
pub struct CertificateFingerprint([u8; 32]);

/// Target OS trust-store scope.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum TrustStoreScope {
    /// Trust only for the current user profile.
    CurrentUser,
    /// Trust for the whole local machine. This generally requires elevation.
    LocalMachine,
}

/// Whether root CA material exists on disk.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CaMaterialState {
    /// All required CA files are present and readable.
    Present,
    /// No CA material exists in the explicit CA directory.
    Missing,
}

/// Status for the local CA material and optional OS trust-store entry.
#[derive(Debug, Clone, Serialize)]
pub struct CaStatus {
    /// CA material state on disk.
    pub material: CaMaterialState,
    /// Directory that contains or is expected to contain CA files.
    pub store_dir: PathBuf,
    /// DER certificate path.
    pub certificate_der_path: PathBuf,
    /// PEM certificate path.
    pub certificate_pem_path: PathBuf,
    /// PEM private-key path.
    pub private_key_pem_path: PathBuf,
    /// Root certificate SHA-256 fingerprint when material is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_sha256: Option<CertificateFingerprint>,
    /// Trust-store state when material is present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust: Option<TrustStoreStatus>,
}

/// Status returned by platform trust-store operations.
#[derive(Debug, Clone, Serialize)]
pub struct TrustStoreStatus {
    /// Trust-store scope that was queried or changed.
    pub scope: TrustStoreScope,
    /// Whether the Abyss root certificate is present in that trust store.
    pub installed: bool,
    /// Root certificate SHA-256 fingerprint used for matching.
    pub fingerprint_sha256: CertificateFingerprint,
}

impl CaStore {
    /// Creates a store rooted at an explicit directory.
    #[must_use]
    pub fn at<P: Into<PathBuf>>(directory: P) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Returns the CA store directory.
    #[must_use]
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Loads CA material and errors when the explicit CA directory is empty.
    ///
    /// This is a pure read for externally provisioned stores and does not
    /// change filesystem permissions. Store owners that must apply their own
    /// persistence policy before reading should use [`Self::load_with`].
    ///
    /// # Errors
    ///
    /// Returns an error when no CA material exists, the store contains only a
    /// subset of the required files, or a present file cannot be read.
    pub fn load_required(&self) -> CaResult<CertificateAuthority> {
        self.load()?.ok_or_else(|| CaError::MissingStore {
            directory: self.directory.clone(),
        })
    }

    /// Loads CA material after the store owner protects a complete store.
    ///
    /// Missing and partial stores are not passed to `persistence`, so a
    /// read-only status or uninstall operation does not create new state.
    ///
    /// # Errors
    ///
    /// Returns an error when the store is partial, cannot be protected, or
    /// contains material that cannot be read.
    pub fn load_with(
        &self,
        persistence: &dyn CaMaterialPersistence,
    ) -> CaResult<Option<CertificateAuthority>> {
        let paths = CaStorePaths::new(&self.directory);
        if paths.presence().all_present() {
            prepare_store(persistence, &self.directory, &paths.private_key_pem)?;
        }
        self.load()
    }

    /// Loads CA material or creates a new local root CA when none exists.
    ///
    /// `persistence` is supplied by the store owner so platform access-control
    /// policy remains outside the MITM layer. It is invoked before an existing
    /// signing key is loaded and before any generated material is written.
    ///
    /// # Errors
    ///
    /// Returns an error when existing material is invalid, generation fails, or
    /// generated files cannot be written to the store directory.
    pub fn load_or_generate_with(
        &self,
        persistence: &dyn CaMaterialPersistence,
    ) -> CaResult<CertificateAuthority> {
        let paths = CaStorePaths::new(&self.directory);
        let presence = paths.presence();
        if presence.all_present() {
            prepare_store(persistence, &self.directory, &paths.private_key_pem)?;
            return self.load_required();
        }
        if presence.all_missing() || presence.public_material_only() {
            prepare_store(persistence, &self.directory, &paths.private_key_pem)?;
            return Self::generate_and_store(&paths, persistence);
        }

        Err(CaError::InvalidStore {
            directory: self.directory.clone(),
            details: format!(
                "expected {ROOT_CERT_DER_FILE_NAME}, {ROOT_CERT_PEM_FILE_NAME}, and {ROOT_KEY_PEM_FILE_NAME} to be present together"
            ),
        })
    }

    /// Loads CA material when all required files are present.
    ///
    /// This is a pure read and does not change filesystem permissions. Store
    /// owners should use [`Self::load_with`] when access policy must be applied
    /// before the signing key is read.
    ///
    /// # Errors
    ///
    /// Returns an error when the store contains only a subset of the required
    /// files or when a present file cannot be read.
    pub fn load(&self) -> CaResult<Option<CertificateAuthority>> {
        let paths = CaStorePaths::new(&self.directory);
        let presence = paths.presence();
        if presence.all_missing() {
            return Ok(None);
        }
        if !presence.all_present() {
            return Err(CaError::InvalidStore {
                directory: self.directory.clone(),
                details: format!(
                    "expected {ROOT_CERT_DER_FILE_NAME}, {ROOT_CERT_PEM_FILE_NAME}, and {ROOT_KEY_PEM_FILE_NAME} to be present together"
                ),
            });
        }

        let certificate_der = read_file("read root CA DER", &paths.certificate_der)?;
        let certificate_pem = read_to_string("read root CA PEM", &paths.certificate_pem)?;
        let private_key_pem =
            read_to_string("read root CA private key PEM", &paths.private_key_pem)?;
        Ok(Some(CertificateAuthority::from_parts(
            certificate_der,
            certificate_pem,
            private_key_pem,
        )))
    }

    /// Reports CA material and trust-store status without generating new files.
    ///
    /// This method does not change filesystem permissions. A store owner that
    /// requires access-policy repair should call [`Self::load_with`] first.
    ///
    /// # Errors
    ///
    /// Returns an error when existing CA material is invalid or when platform
    /// trust-store status cannot be queried.
    pub fn status(&self, scope: TrustStoreScope) -> CaResult<CaStatus> {
        let paths = CaStorePaths::new(&self.directory);
        let Some(authority) = self.load()? else {
            return Ok(CaStatus {
                material: CaMaterialState::Missing,
                store_dir: self.directory.clone(),
                certificate_der_path: paths.certificate_der,
                certificate_pem_path: paths.certificate_pem,
                private_key_pem_path: paths.private_key_pem,
                fingerprint_sha256: None,
                trust: None,
            });
        };

        let trust = authority.trust_status(scope)?;
        let fingerprint_sha256 = authority.fingerprint_sha256;
        Ok(CaStatus {
            material: CaMaterialState::Present,
            store_dir: self.directory.clone(),
            certificate_der_path: paths.certificate_der,
            certificate_pem_path: paths.certificate_pem,
            private_key_pem_path: paths.private_key_pem,
            fingerprint_sha256: Some(fingerprint_sha256),
            trust: Some(trust),
        })
    }

    fn generate_and_store(
        paths: &CaStorePaths,
        persistence: &dyn CaMaterialPersistence,
    ) -> CaResult<CertificateAuthority> {
        // CA generation can run before any MITM engine exists, so install the
        // rustls provider before rcgen generates and signs the root keypair.
        crate::tls::install_default_crypto_provider();
        let key_pair = KeyPair::generate().map_err(|source| CaError::Generation {
            operation: "generate root CA key",
            source,
        })?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Abyss Local MITM Root CA");
        distinguished_name.push(DnType::OrganizationName, "Lexmount");

        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];

        let certificate = params
            .self_signed(&key_pair)
            .map_err(|source| CaError::Generation {
                operation: "self-sign root CA certificate",
                source,
            })?;
        let certificate_der = certificate.der().as_ref().to_vec();
        let certificate_pem = certificate.pem();
        let private_key_pem = key_pair.serialize_pem();

        write_public_file(
            persistence,
            "write root CA DER",
            &paths.certificate_der,
            &certificate_der,
        )?;
        write_public_file(
            persistence,
            "write root CA PEM",
            &paths.certificate_pem,
            certificate_pem.as_bytes(),
        )?;
        write_private_file(
            persistence,
            "write root CA private key PEM",
            &paths.private_key_pem,
            private_key_pem.as_bytes(),
        )?;

        Ok(CertificateAuthority::from_parts(
            certificate_der,
            certificate_pem,
            private_key_pem,
        ))
    }
}

impl CertificateAuthority {
    pub(crate) fn from_parts(
        certificate_der: Vec<u8>,
        certificate_pem: String,
        private_key_pem: String,
    ) -> Self {
        let fingerprint_sha256 = CertificateFingerprint::from_der(&certificate_der);
        Self {
            certificate_der: certificate_der.into_boxed_slice(),
            certificate_pem,
            private_key_pem,
            fingerprint_sha256,
        }
    }

    /// Returns the DER-encoded root certificate public material.
    #[must_use]
    pub fn certificate_der(&self) -> &[u8] {
        self.certificate_der.as_ref()
    }

    /// Returns the PEM-encoded root certificate public material.
    #[must_use]
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }

    /// Returns the PEM-encoded root private key.
    ///
    /// Callers should not expose this value outside the local MITM runtime.
    #[must_use]
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    /// Returns the SHA-256 fingerprint of the root certificate DER bytes.
    #[must_use]
    pub const fn fingerprint_sha256(&self) -> &CertificateFingerprint {
        &self.fingerprint_sha256
    }

    /// Installs this root certificate into an OS trust store.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform adapter cannot open or update the
    /// requested trust store.
    pub fn install(&self, scope: TrustStoreScope) -> CaResult<TrustStoreStatus> {
        platform::install_root_certificate(&self.certificate_der, &self.fingerprint_sha256, scope)
    }

    /// Removes this root certificate from an OS trust store.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform adapter cannot open or update the
    /// requested trust store.
    pub fn uninstall(&self, scope: TrustStoreScope) -> CaResult<TrustStoreStatus> {
        platform::uninstall_root_certificate(&self.fingerprint_sha256, scope)
    }

    /// Queries whether this root certificate is trusted by the OS.
    ///
    /// # Errors
    ///
    /// Returns an error when the platform adapter cannot query the requested
    /// trust store.
    pub fn trust_status(&self, scope: TrustStoreScope) -> CaResult<TrustStoreStatus> {
        platform::root_certificate_status(&self.fingerprint_sha256, scope)
    }
}

impl CertificateFingerprint {
    /// Computes a SHA-256 fingerprint from DER-encoded certificate bytes.
    #[must_use]
    pub fn from_der(der: &[u8]) -> Self {
        let digest = Sha256::digest(der);
        Self(digest.into())
    }

    /// Returns the raw 32-byte SHA-256 digest.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the lowercase hexadecimal digest.
    #[must_use]
    pub fn to_hex(&self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Debug for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl fmt::Display for CertificateFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for CertificateFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

struct CaStorePaths {
    certificate_der: PathBuf,
    certificate_pem: PathBuf,
    private_key_pem: PathBuf,
}

impl CaStorePaths {
    fn new(directory: &Path) -> Self {
        Self {
            certificate_der: directory.join(ROOT_CERT_DER_FILE_NAME),
            certificate_pem: directory.join(ROOT_CERT_PEM_FILE_NAME),
            private_key_pem: directory.join(ROOT_KEY_PEM_FILE_NAME),
        }
    }

    fn presence(&self) -> CaStorePresence {
        CaStorePresence {
            certificate_der: self.certificate_der.exists(),
            certificate_pem: self.certificate_pem.exists(),
            private_key_pem: self.private_key_pem.exists(),
        }
    }
}

struct CaStorePresence {
    certificate_der: bool,
    certificate_pem: bool,
    private_key_pem: bool,
}

impl CaStorePresence {
    const fn all_missing(&self) -> bool {
        !self.certificate_der && !self.certificate_pem && !self.private_key_pem
    }

    const fn all_present(&self) -> bool {
        self.certificate_der && self.certificate_pem && self.private_key_pem
    }

    const fn public_material_only(&self) -> bool {
        self.certificate_der && self.certificate_pem && !self.private_key_pem
    }
}

fn read_file(operation: &'static str, path: &Path) -> CaResult<Vec<u8>> {
    fs::read(path).map_err(|source| CaError::io(operation, path, source))
}

fn read_to_string(operation: &'static str, path: &Path) -> CaResult<String> {
    fs::read_to_string(path).map_err(|source| CaError::io(operation, path, source))
}

fn prepare_store(
    persistence: &dyn CaMaterialPersistence,
    directory: &Path,
    private_key: &Path,
) -> CaResult<()> {
    persistence
        .prepare_store(directory, private_key)
        .map_err(|source| CaError::io("prepare CA material store", directory, source))
}

fn write_public_file(
    persistence: &dyn CaMaterialPersistence,
    operation: &'static str,
    path: &Path,
    contents: &[u8],
) -> CaResult<()> {
    persistence
        .write_public(path, contents)
        .map_err(|source| CaError::io(operation, path, source))
}

fn write_private_file(
    persistence: &dyn CaMaterialPersistence,
    operation: &'static str,
    path: &Path,
    contents: &[u8],
) -> CaResult<()> {
    persistence
        .write_private(path, contents)
        .map_err(|source| CaError::io(operation, path, source))
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2)
        .expect("hex output capacity should not overflow");
    let mut encoded = String::with_capacity(capacity);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4_u8)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f_u8)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::{
        cell::RefCell,
        fs,
        io::{self, Write as _},
        path::{Path, PathBuf},
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::{
        CaError, CaMaterialPersistence, CaMaterialState, CaStore, CertificateFingerprint,
        ROOT_CERT_DER_FILE_NAME, ROOT_CERT_PEM_FILE_NAME, ROOT_KEY_PEM_FILE_NAME,
    };

    const FINGERPRINT_HEX_LEN: usize = 64;

    #[test]
    fn load_returns_missing_for_empty_store() {
        let store = CaStore::at(unique_test_dir("empty"));

        let loaded = store.load().expect("empty store should be readable");

        assert!(loaded.is_none());
    }

    #[test]
    fn load_required_errors_for_empty_store() {
        let store = CaStore::at(unique_test_dir("required-missing"));

        let error = store
            .load_required()
            .expect_err("required CA material should reject an empty store");

        assert!(
            matches!(error, CaError::MissingStore { .. }),
            "empty explicit CA directory should be reported as missing"
        );
    }

    #[test]
    fn load_reads_external_ca_material() {
        let dir = unique_test_dir("external");
        write_ca_fixture(&dir);
        let store = CaStore::at(&dir);

        let ca = store
            .load_required()
            .expect("external CA fixture should load");

        assert_eq!(ca.certificate_der(), TEST_CERT_DER);
        assert!(
            ca.certificate_pem().contains("BEGIN CERTIFICATE"),
            "external PEM certificate should be exposed"
        );
        assert!(
            ca.private_key_pem().contains("BEGIN PRIVATE KEY"),
            "external private key should be exposed"
        );
    }

    #[test]
    fn load_or_generate_creates_missing_store() {
        let dir = unique_test_dir("generate-missing");
        let store = CaStore::at(&dir);
        let persistence = RecordingPersistence::successful();

        let ca = store
            .load_or_generate_with(&persistence)
            .expect("missing CA store should be generated");

        assert!(dir.join(ROOT_CERT_DER_FILE_NAME).is_file());
        assert!(dir.join(ROOT_CERT_PEM_FILE_NAME).is_file());
        assert!(dir.join(ROOT_KEY_PEM_FILE_NAME).is_file());
        assert!(
            ca.certificate_pem().contains("BEGIN CERTIFICATE"),
            "generated certificate PEM should be exposed"
        );
        assert!(
            ca.private_key_pem().contains("BEGIN PRIVATE KEY"),
            "generated private key PEM should be exposed"
        );
        assert_eq!(
            persistence.take_calls(),
            vec![
                PersistenceCall::Prepare {
                    directory: dir.clone(),
                    private_key: dir.join(ROOT_KEY_PEM_FILE_NAME),
                },
                PersistenceCall::WritePublic(dir.join(ROOT_CERT_DER_FILE_NAME)),
                PersistenceCall::WritePublic(dir.join(ROOT_CERT_PEM_FILE_NAME)),
                PersistenceCall::WritePrivate(dir.join(ROOT_KEY_PEM_FILE_NAME)),
            ],
            "the store must be secured before public material and the signing key are written"
        );
    }

    #[test]
    fn load_or_generate_replaces_public_only_store() {
        let dir = unique_test_dir("generate-public-only");
        fs::create_dir_all(&dir).expect("test directory should be created");
        fs::write(dir.join(ROOT_CERT_DER_FILE_NAME), TEST_CERT_DER)
            .expect("test DER certificate should be written");
        fs::write(dir.join(ROOT_CERT_PEM_FILE_NAME), TEST_CERT_PEM)
            .expect("test PEM certificate should be written");
        let store = CaStore::at(&dir);
        let persistence = RecordingPersistence::successful();

        let ca = store
            .load_or_generate_with(&persistence)
            .expect("public-only CA store should be replaced");

        assert_ne!(ca.certificate_der(), TEST_CERT_DER);
        assert!(dir.join(ROOT_KEY_PEM_FILE_NAME).is_file());
    }

    #[test]
    fn load_or_generate_prepares_an_existing_store_before_reading_it() {
        let dir = unique_test_dir("prepare-existing");
        write_ca_fixture(&dir);
        let persistence = ReplacingKeyPersistence;

        let ca = CaStore::at(&dir)
            .load_or_generate_with(&persistence)
            .expect("a complete CA store should load after hardening");

        assert_eq!(
            ca.private_key_pem(),
            REPLACEMENT_TEST_KEY_PEM,
            "the persistence adapter must run before the existing key is read"
        );
    }

    #[test]
    fn load_with_prepares_a_complete_store_before_reading_it() {
        let dir = unique_test_dir("load-with-prepare-existing");
        write_ca_fixture(&dir);

        let ca = CaStore::at(&dir)
            .load_with(&ReplacingKeyPersistence)
            .expect("a complete store should load after preparation")
            .expect("the complete store should be present");

        assert_eq!(
            ca.private_key_pem(),
            REPLACEMENT_TEST_KEY_PEM,
            "the persistence adapter must run before the existing key is read"
        );
    }

    #[test]
    fn load_with_does_not_prepare_a_missing_store() {
        let dir = unique_test_dir("load-with-missing");
        let persistence = RecordingPersistence::successful();

        assert!(
            CaStore::at(&dir)
                .load_with(&persistence)
                .expect("a missing store should be readable")
                .is_none()
        );
        assert!(
            persistence.take_calls().is_empty(),
            "reading a missing store must not create or protect state"
        );
    }

    #[test]
    fn load_with_does_not_prepare_a_partial_store() {
        let dir = unique_test_dir("load-with-partial");
        fs::create_dir_all(&dir).expect("partial store directory should create");
        fs::write(dir.join(ROOT_CERT_DER_FILE_NAME), TEST_CERT_DER)
            .expect("partial certificate should write");
        let persistence = RecordingPersistence::successful();

        let error = CaStore::at(&dir)
            .load_with(&persistence)
            .expect_err("a partial store must be rejected");

        assert!(matches!(error, CaError::InvalidStore { .. }));
        assert!(
            persistence.take_calls().is_empty(),
            "reading a partial store must not create or protect state"
        );
    }

    #[test]
    fn load_or_generate_propagates_prepare_errors_with_store_context() {
        let dir = unique_test_dir("prepare-error");
        let persistence = FailingPersistence::at(FailurePoint::Prepare);

        let error = CaStore::at(&dir)
            .load_or_generate_with(&persistence)
            .expect_err("a persistence preparation error must fail generation");

        assert!(matches!(
            error,
            CaError::Io {
                operation: "prepare CA material store",
                path,
                source,
            } if path == dir && source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn load_or_generate_propagates_private_write_errors_with_key_context() {
        let dir = unique_test_dir("private-write-error");
        let persistence = FailingPersistence::at(FailurePoint::PrivateWrite);

        let error = CaStore::at(&dir)
            .load_or_generate_with(&persistence)
            .expect_err("a private-key persistence error must fail generation");

        assert!(matches!(
            error,
            CaError::Io {
                operation: "write root CA private key PEM",
                path,
                source,
            } if path == dir.join(ROOT_KEY_PEM_FILE_NAME)
                && source.kind() == io::ErrorKind::PermissionDenied
        ));
    }

    #[test]
    fn status_does_not_generate_missing_store() {
        let store = CaStore::at(unique_test_dir("status-missing"));

        let status = store
            .status(super::TrustStoreScope::CurrentUser)
            .expect("missing store status should not hit platform trust APIs");

        assert_eq!(status.material, CaMaterialState::Missing);
        assert_eq!(status.fingerprint_sha256, None);
        assert!(status.trust.is_none());
        assert!(
            !status.certificate_der_path.exists(),
            "status should not create CA files"
        );
    }

    #[test]
    fn partial_store_is_rejected() {
        let dir = unique_test_dir("partial");
        fs::create_dir_all(&dir).expect("test directory should be created");
        fs::write(dir.join(ROOT_CERT_DER_FILE_NAME), b"not-a-cert")
            .expect("partial file should be written");
        let store = CaStore::at(dir);

        let error = store
            .load()
            .expect_err("partial CA material should be rejected");

        assert!(
            error.to_string().contains("expected"),
            "error should explain the required file set"
        );
    }

    #[test]
    fn fingerprint_formats_as_lowercase_hex() {
        let fingerprint = CertificateFingerprint::from_der(b"certificate bytes");
        let text = fingerprint.to_string();

        assert_eq!(text.len(), FINGERPRINT_HEX_LEN);
        assert!(
            text.chars().all(|character| character.is_ascii_hexdigit()),
            "fingerprint should contain hex digits"
        );
        assert_eq!(text, text.to_ascii_lowercase());
    }

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be after Unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "abyss-mitm-ca-{name}-{}-{timestamp}",
            std::process::id()
        ))
    }

    const TEST_CERT_DER: &[u8] = b"enterprise root ca fixture";
    const TEST_CERT_PEM: &str =
        "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
    const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n";
    const REPLACEMENT_TEST_KEY_PEM: &str =
        "-----BEGIN PRIVATE KEY-----\ncmVwbGFjZWQ=\n-----END PRIVATE KEY-----\n";

    fn write_ca_fixture(directory: &std::path::Path) {
        fs::create_dir_all(directory).expect("test CA directory should be created");
        fs::write(directory.join(ROOT_CERT_DER_FILE_NAME), TEST_CERT_DER)
            .expect("test DER certificate should be written");
        fs::write(directory.join(ROOT_CERT_PEM_FILE_NAME), TEST_CERT_PEM)
            .expect("test PEM certificate should be written");
        fs::write(directory.join(ROOT_KEY_PEM_FILE_NAME), TEST_KEY_PEM)
            .expect("test private key should be written");
    }

    #[derive(Debug, PartialEq)]
    enum PersistenceCall {
        Prepare {
            directory: PathBuf,
            private_key: PathBuf,
        },
        WritePublic(PathBuf),
        WritePrivate(PathBuf),
    }

    struct RecordingPersistence {
        calls: RefCell<Vec<PersistenceCall>>,
    }

    impl RecordingPersistence {
        fn successful() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
            }
        }

        fn take_calls(&self) -> Vec<PersistenceCall> {
            self.calls.take()
        }

        fn write_file(path: &Path, contents: &[u8]) -> io::Result<()> {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(path)?;
            file.write_all(contents)?;
            file.sync_all()
        }
    }

    impl CaMaterialPersistence for RecordingPersistence {
        fn prepare_store(&self, directory: &Path, private_key: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push(PersistenceCall::Prepare {
                directory: directory.to_path_buf(),
                private_key: private_key.to_path_buf(),
            });
            fs::create_dir_all(directory)
        }

        fn write_public(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(PersistenceCall::WritePublic(path.to_path_buf()));
            Self::write_file(path, contents)
        }

        fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(PersistenceCall::WritePrivate(path.to_path_buf()));
            Self::write_file(path, contents)
        }
    }

    struct ReplacingKeyPersistence;

    impl CaMaterialPersistence for ReplacingKeyPersistence {
        fn prepare_store(&self, _directory: &Path, private_key: &Path) -> io::Result<()> {
            fs::write(private_key, REPLACEMENT_TEST_KEY_PEM)
        }

        fn write_public(&self, _path: &Path, _contents: &[u8]) -> io::Result<()> {
            panic!("an existing complete store must not rewrite public material")
        }

        fn write_private(&self, _path: &Path, _contents: &[u8]) -> io::Result<()> {
            panic!("an existing complete store must not rewrite its private key")
        }
    }

    enum FailurePoint {
        Prepare,
        PrivateWrite,
    }

    struct FailingPersistence {
        failure: FailurePoint,
    }

    impl FailingPersistence {
        const fn at(failure: FailurePoint) -> Self {
            Self { failure }
        }

        fn failure() -> io::Error {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected persistence failure",
            )
        }
    }

    impl CaMaterialPersistence for FailingPersistence {
        fn prepare_store(&self, directory: &Path, _private_key: &Path) -> io::Result<()> {
            if matches!(&self.failure, FailurePoint::Prepare) {
                return Err(Self::failure());
            }
            fs::create_dir_all(directory)
        }

        fn write_public(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
            RecordingPersistence::write_file(path, contents)
        }

        fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
            if matches!(&self.failure, FailurePoint::PrivateWrite) {
                return Err(Self::failure());
            }
            RecordingPersistence::write_file(path, contents)
        }
    }
}
