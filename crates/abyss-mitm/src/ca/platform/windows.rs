//! Windows root CA trust-store adapter.
//!
//! Windows keeps trusted roots in system certificate stores. The Abyss MITM
//! layer currently targets the `ROOT` store and matches certificates by the
//! SHA-256 fingerprint of their encoded DER bytes, so uninstall only removes
//! the exact externally supplied root certificate.

use super::{
    super::{CaError, CaResult, CertificateFingerprint, TrustStoreScope, TrustStoreStatus},
    TrustStoreAdapter,
};
use crate::sys::windows::cert_store::{
    AddDisposition, CertificateEncoding, CertificateStore, CertificateStoreError,
    SystemStoreLocation, SystemStoreName,
};

/// Windows implementation of the Abyss root CA trust-store adapter.
pub(super) struct PlatformTrustStore;

impl TrustStoreAdapter for PlatformTrustStore {
    fn install_root_certificate(
        &self,
        certificate_der: &[u8],
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let store = root_store(scope)?;
        store
            .add_encoded_certificate(
                CertificateEncoding::X509OrPkcs7,
                certificate_der,
                AddDisposition::ReplaceExisting,
            )
            .map_err(|source| platform_error(&source))?;
        self.root_certificate_status(fingerprint, scope)
    }

    fn uninstall_root_certificate(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let store = root_store(scope)?;
        if let Some(context) = find_by_sha256(&store, fingerprint)? {
            context.delete().map_err(|source| platform_error(&source))?;
        }
        Ok(TrustStoreStatus {
            scope,
            installed: false,
            fingerprint_sha256: fingerprint.clone(),
        })
    }

    fn root_certificate_status(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus> {
        let store = root_store(scope)?;
        let installed = find_by_sha256(&store, fingerprint)?.is_some();
        Ok(TrustStoreStatus {
            scope,
            installed,
            fingerprint_sha256: fingerprint.clone(),
        })
    }
}

fn root_store(scope: TrustStoreScope) -> CaResult<CertificateStore> {
    CertificateStore::open_system(SystemStoreName::Root, scope.into())
        .map_err(|source| platform_error(&source))
}

fn find_by_sha256(
    store: &CertificateStore,
    fingerprint: &CertificateFingerprint,
) -> CaResult<Option<crate::sys::windows::cert_store::CertificateContext>> {
    store
        .find_certificate(|encoded| {
            CertificateFingerprint::from_der(encoded).as_bytes() == fingerprint.as_bytes()
        })
        .map_err(|source| platform_error(&source))
}

impl From<TrustStoreScope> for SystemStoreLocation {
    fn from(scope: TrustStoreScope) -> Self {
        match scope {
            TrustStoreScope::CurrentUser => Self::CurrentUser,
            TrustStoreScope::LocalMachine => Self::LocalMachine,
        }
    }
}

fn platform_error(source: &CertificateStoreError) -> CaError {
    CaError::platform("Windows Root certificate store", source.to_string())
}
