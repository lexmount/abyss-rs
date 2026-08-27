//! TLS configuration helpers for transparent MITM flows.
//!
//! This module converts externally supplied root CA material into per-SNI
//! server certificates. The proxy worker uses these safe helpers instead of
//! constructing rustls/rcgen objects inline.

use std::{
    fmt,
    sync::{Arc, Once},
};

use rcgen::{
    CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use thiserror::Error;
use time::{Duration, OffsetDateTime};
use tokio_rustls::rustls::{
    self, ClientConfig, RootCertStore, ServerConfig, pki_types::ServerName,
};

use crate::CertificateAuthority;

static INSTALL_CRYPTO_PROVIDER: Once = Once::new();

/// Installs the crate's preferred rustls crypto provider.
///
/// `abyss-mitm` enables the `aws_lc_rs` rustls backend. Installing it
/// explicitly avoids process-level ambiguity when another workspace crate pulls
/// a rustls dependency with different default features.
pub fn install_default_crypto_provider() {
    INSTALL_CRYPTO_PROVIDER.call_once(|| {
        let _already_installed = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Root CA wrapper used to sign one leaf certificate per intercepted SNI.
pub struct MitmTlsAuthority {
    issuer: Arc<Issuer<'static, KeyPair>>,
}

/// Errors returned while preparing TLS MITM state.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TlsMitmError {
    /// The externally supplied root CA material could not be parsed.
    #[error("invalid MITM root CA material: {0}")]
    CertificateAuthority(#[source] rcgen::Error),
    /// The requested SNI cannot be used as a rustls server name.
    #[error("invalid TLS server name `{server_name}`: {details}")]
    InvalidServerName {
        /// SNI value observed from the client.
        server_name: String,
        /// Validation details from rustls.
        details: String,
    },
    /// A leaf certificate could not be generated for the observed SNI.
    #[error("failed to generate MITM leaf certificate for `{server_name}`: {source}")]
    LeafCertificate {
        /// SNI value observed from the client.
        server_name: String,
        /// Source rcgen error.
        #[source]
        source: rcgen::Error,
    },
    /// rustls rejected the generated certificate/key pair.
    #[error("invalid TLS MITM server configuration: {0}")]
    ServerConfig(#[source] rustls::Error),
    /// The blocking certificate generation worker failed.
    #[error("TLS MITM certificate worker failed")]
    CertificateWorker(#[source] tokio::task::JoinError),
}

impl MitmTlsAuthority {
    /// Builds a TLS MITM authority from externally supplied root CA material.
    ///
    /// # Errors
    ///
    /// Returns an error when the PEM root certificate or PEM private key cannot
    /// be parsed as a signing CA.
    pub fn from_ca(ca: &CertificateAuthority) -> Result<Self, TlsMitmError> {
        // Proxy startup may load an existing CA without going through CA
        // generation, so the TLS use path installs the provider too.
        install_default_crypto_provider();
        let key_pair =
            KeyPair::from_pem(ca.private_key_pem()).map_err(TlsMitmError::CertificateAuthority)?;
        let issuer = Issuer::from_ca_cert_pem(ca.certificate_pem(), key_pair)
            .map_err(TlsMitmError::CertificateAuthority)?;
        Ok(Self {
            issuer: Arc::new(issuer),
        })
    }

    /// Creates a rustls server config with a leaf certificate for `server_name`.
    ///
    /// # Errors
    ///
    /// Returns an error when `server_name` is not a valid DNS name, leaf signing
    /// fails, or rustls rejects the generated leaf/key pair.
    pub async fn server_config_for_sni(
        &self,
        server_name: &str,
    ) -> Result<Arc<ServerConfig>, TlsMitmError> {
        validate_server_name(server_name)?;

        let issuer = Arc::clone(&self.issuer);
        let server_name = server_name.to_owned();
        tokio::task::spawn_blocking(move || server_config_for_sni_blocking(&issuer, server_name))
            .await
            .map_err(TlsMitmError::CertificateWorker)?
    }
}

impl fmt::Debug for MitmTlsAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MitmTlsAuthority")
            .field("issuer", &"<redacted>")
            .finish()
    }
}

/// Builds a client config that verifies upstream TLS with Mozilla `WebPKI` roots.
#[must_use]
pub fn webpki_upstream_client_config() -> Arc<ClientConfig> {
    // Upstream TLS client config construction also depends on rustls' process
    // default provider; keep this helper self-contained for callers.
    install_default_crypto_provider();
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Converts a DNS name into the owned rustls server-name type.
///
/// # Errors
///
/// Returns an error when rustls rejects the supplied DNS name.
pub fn validate_server_name(server_name: &str) -> Result<ServerName<'static>, TlsMitmError> {
    ServerName::try_from(server_name.to_owned()).map_err(|source| TlsMitmError::InvalidServerName {
        server_name: server_name.to_owned(),
        details: source.to_string(),
    })
}

fn leaf_certificate_params(server_name: &str) -> Result<CertificateParams, rcgen::Error> {
    let mut params = CertificateParams::new(vec![server_name.to_owned()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, server_name);
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);
    let now = OffsetDateTime::now_utc();
    params.not_before = now.checked_sub(Duration::days(1)).unwrap_or(now);
    params.not_after = now.checked_add(Duration::days(30)).unwrap_or(now);
    Ok(params)
}

fn server_config_for_sni_blocking(
    issuer: &Issuer<'static, KeyPair>,
    server_name: String,
) -> Result<Arc<ServerConfig>, TlsMitmError> {
    let key_pair = KeyPair::generate().map_err(|source| TlsMitmError::LeafCertificate {
        server_name: server_name.clone(),
        source,
    })?;
    // TODO: consider mirroring selected fields from the upstream server
    // certificate, such as SANs, validity, and key usages, if we hit client
    // compatibility issues with the current minimal SNI-only leaf.
    let leaf = leaf_certificate_params(&server_name)
        .and_then(|params| params.signed_by(&key_pair, issuer))
        .map_err(|source| TlsMitmError::LeafCertificate {
            server_name,
            source,
        })?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![leaf.der().clone()], key_pair.into())
        .map_err(TlsMitmError::ServerConfig)?;

    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, DistinguishedName, KeyUsagePurpose};

    use super::*;

    fn test_ca() -> CertificateAuthority {
        // Tests generate rcgen keys directly, bypassing CaStore's provider
        // setup, so install it in the fixture before key generation.
        install_default_crypto_provider();
        let key_pair = KeyPair::generate().expect("test CA key should generate");
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, "Abyss Test Root CA");
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
            .expect("test root CA should self-sign");
        CertificateAuthority::from_parts(
            certificate.der().to_vec(),
            certificate.pem(),
            key_pair.serialize_pem(),
        )
    }

    #[tokio::test]
    async fn signs_leaf_certificate_for_sni() {
        let authority =
            MitmTlsAuthority::from_ca(&test_ca()).expect("test CA should parse as issuer");

        let config = authority
            .server_config_for_sni("example.test")
            .await
            .expect("leaf certificate should produce rustls config");

        assert!(
            !config.alpn_protocols.iter().any(Vec::is_empty),
            "server config should not contain empty ALPN values"
        );
    }
}
