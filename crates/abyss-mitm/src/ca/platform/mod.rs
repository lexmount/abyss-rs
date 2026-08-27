//! Platform-specific root CA trust-store adapters.
//!
//! The public CA API in `ca::mod` stays platform-neutral. This module selects
//! one OS adapter from the sibling directories so callers can install, remove,
//! and query the Abyss root CA without knowing how each OS stores trust anchors.

use super::{CaResult, CertificateFingerprint, TrustStoreScope, TrustStoreStatus};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// Platform trust-store capability used by the CA lifecycle layer.
///
/// Every OS adapter implements this trait with the same semantics: matching is
/// based on the Abyss root certificate fingerprint, install stores public root
/// material only, and uninstall removes only that exact certificate.
pub(super) trait TrustStoreAdapter {
    /// Installs a root certificate into the selected platform trust store.
    fn install_root_certificate(
        &self,
        certificate_der: &[u8],
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus>;

    /// Removes a root certificate from the selected platform trust store.
    fn uninstall_root_certificate(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus>;

    /// Queries whether a root certificate is present in the selected trust store.
    fn root_certificate_status(
        &self,
        fingerprint: &CertificateFingerprint,
        scope: TrustStoreScope,
    ) -> CaResult<TrustStoreStatus>;
}

/// Installs a root certificate into the selected platform trust store.
pub(super) fn install_root_certificate(
    certificate_der: &[u8],
    fingerprint: &CertificateFingerprint,
    scope: TrustStoreScope,
) -> CaResult<TrustStoreStatus> {
    install_root_certificate_with_adapter(
        &implementation::PlatformTrustStore,
        certificate_der,
        fingerprint,
        scope,
    )
}

/// Removes a root certificate from the selected platform trust store.
pub(super) fn uninstall_root_certificate(
    fingerprint: &CertificateFingerprint,
    scope: TrustStoreScope,
) -> CaResult<TrustStoreStatus> {
    uninstall_root_certificate_with_adapter(&implementation::PlatformTrustStore, fingerprint, scope)
}

/// Queries whether a root certificate is present in the selected trust store.
pub(super) fn root_certificate_status(
    fingerprint: &CertificateFingerprint,
    scope: TrustStoreScope,
) -> CaResult<TrustStoreStatus> {
    root_certificate_status_with_adapter(&implementation::PlatformTrustStore, fingerprint, scope)
}

fn install_root_certificate_with_adapter<A: TrustStoreAdapter>(
    adapter: &A,
    certificate_der: &[u8],
    fingerprint: &CertificateFingerprint,
    scope: TrustStoreScope,
) -> CaResult<TrustStoreStatus> {
    // Keep installation idempotent. A package upgrade commonly runs the CA
    // install command again; re-importing an already trusted certificate can
    // trigger another platform authorization prompt even though the CA has
    // not changed.
    let status = adapter.root_certificate_status(fingerprint, scope)?;
    if status.installed {
        return Ok(status);
    }
    adapter.install_root_certificate(certificate_der, fingerprint, scope)
}

fn uninstall_root_certificate_with_adapter<A: TrustStoreAdapter>(
    adapter: &A,
    fingerprint: &CertificateFingerprint,
    scope: TrustStoreScope,
) -> CaResult<TrustStoreStatus> {
    adapter.uninstall_root_certificate(fingerprint, scope)
}

fn root_certificate_status_with_adapter<A: TrustStoreAdapter>(
    adapter: &A,
    fingerprint: &CertificateFingerprint,
    scope: TrustStoreScope,
) -> CaResult<TrustStoreStatus> {
    adapter.root_certificate_status(fingerprint, scope)
}

#[cfg(target_os = "linux")]
mod implementation {
    pub(super) use super::linux::PlatformTrustStore;
}

#[cfg(target_os = "macos")]
mod implementation {
    pub(super) use super::macos::PlatformTrustStore;
}

#[cfg(windows)]
mod implementation {
    pub(super) use super::windows::PlatformTrustStore;
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::{
        CaResult, CertificateFingerprint, TrustStoreAdapter, TrustStoreScope, TrustStoreStatus,
        install_root_certificate_with_adapter, root_certificate_status_with_adapter,
        uninstall_root_certificate_with_adapter,
    };

    #[test]
    fn install_skips_adapter_when_certificate_is_already_installed() {
        let adapter = RecordingTrustStoreAdapter::new(true);
        let fingerprint = CertificateFingerprint::from_der(b"test certificate");

        let status = install_root_certificate_with_adapter(
            &adapter,
            b"der",
            &fingerprint,
            TrustStoreScope::CurrentUser,
        )
        .expect("fake adapter should install");

        assert!(status.installed);
        assert_eq!(status.scope, TrustStoreScope::CurrentUser);
        assert_eq!(status.fingerprint_sha256, fingerprint);
        assert_eq!(adapter.install_calls.get(), 0);
    }

    #[test]
    fn install_delegates_to_adapter_when_certificate_is_missing() {
        let adapter = RecordingTrustStoreAdapter::new(false);
        let fingerprint = CertificateFingerprint::from_der(b"test certificate");

        let status = install_root_certificate_with_adapter(
            &adapter,
            b"der",
            &fingerprint,
            TrustStoreScope::CurrentUser,
        )
        .expect("fake adapter should install");

        assert!(status.installed);
        assert_eq!(status.scope, TrustStoreScope::CurrentUser);
        assert_eq!(status.fingerprint_sha256, fingerprint);
        assert_eq!(adapter.install_calls.get(), 1);
    }

    #[test]
    fn status_delegates_to_adapter() {
        let adapter = RecordingTrustStoreAdapter::new(true);
        let fingerprint = CertificateFingerprint::from_der(b"test certificate");

        let status = root_certificate_status_with_adapter(
            &adapter,
            &fingerprint,
            TrustStoreScope::LocalMachine,
        )
        .expect("fake adapter should report status");

        assert!(status.installed);
        assert_eq!(status.scope, TrustStoreScope::LocalMachine);
    }

    #[test]
    fn uninstall_delegates_to_adapter() {
        let adapter = RecordingTrustStoreAdapter::new(true);
        let fingerprint = CertificateFingerprint::from_der(b"test certificate");

        let status = uninstall_root_certificate_with_adapter(
            &adapter,
            &fingerprint,
            TrustStoreScope::CurrentUser,
        )
        .expect("fake adapter should uninstall");

        assert!(!status.installed);
        assert_eq!(status.fingerprint_sha256, fingerprint);
        assert!(!adapter.installed.get());
    }

    struct RecordingTrustStoreAdapter {
        installed: Cell<bool>,
        install_calls: Cell<usize>,
    }

    impl RecordingTrustStoreAdapter {
        fn new(installed: bool) -> Self {
            Self {
                installed: Cell::new(installed),
                install_calls: Cell::new(0),
            }
        }
    }

    impl TrustStoreAdapter for RecordingTrustStoreAdapter {
        fn install_root_certificate(
            &self,
            _certificate_der: &[u8],
            fingerprint: &CertificateFingerprint,
            scope: TrustStoreScope,
        ) -> CaResult<TrustStoreStatus> {
            self.install_calls
                .set(self.install_calls.get().saturating_add(1));
            self.installed.set(true);
            Ok(TrustStoreStatus {
                scope,
                installed: self.installed.get(),
                fingerprint_sha256: fingerprint.clone(),
            })
        }

        fn uninstall_root_certificate(
            &self,
            fingerprint: &CertificateFingerprint,
            scope: TrustStoreScope,
        ) -> CaResult<TrustStoreStatus> {
            self.installed.set(false);
            Ok(TrustStoreStatus {
                scope,
                installed: self.installed.get(),
                fingerprint_sha256: fingerprint.clone(),
            })
        }

        fn root_certificate_status(
            &self,
            fingerprint: &CertificateFingerprint,
            scope: TrustStoreScope,
        ) -> CaResult<TrustStoreStatus> {
            Ok(TrustStoreStatus {
                scope,
                installed: self.installed.get(),
                fingerprint_sha256: fingerprint.clone(),
            })
        }
    }
}
