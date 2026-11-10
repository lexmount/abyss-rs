//! Transport to the proxy itself, with trust and TLS identity separate from target TLS.

use std::sync::Arc;

use tokio::{
    net::TcpStream,
    time::{Instant, timeout_at},
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, ServerName, pem::PemObject as _},
    },
};

use super::{
    ProxyConnectStage, UpstreamProxyConfig, UpstreamProxyConfigError, UpstreamProxyError,
    config::read_material,
};
use crate::{BoxedDuplexStream, TargetAuthority};

#[derive(Clone)]
pub(super) enum ProxyTransport {
    Http,
    Https {
        config: Arc<ClientConfig>,
        server_name: ServerName<'static>,
    },
}

impl ProxyTransport {
    pub(super) fn new(
        config: &UpstreamProxyConfig,
        endpoint: &TargetAuthority,
    ) -> Result<Self, UpstreamProxyConfigError> {
        if !config.endpoint.starts_with("https://") {
            return Ok(Self::Http);
        }
        crate::tls::install_default_crypto_provider();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = &config.ca_file {
            let pem = read_material(path, 1024 * 1024)?;
            let certificates = CertificateDer::pem_slice_iter(&pem)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| UpstreamProxyConfigError("invalid proxy CA PEM bundle"))?;
            if certificates.is_empty() {
                return Err(UpstreamProxyConfigError(
                    "proxy CA PEM bundle contains no certificates",
                ));
            }
            for certificate in certificates {
                roots
                    .add(certificate)
                    .map_err(|_| UpstreamProxyConfigError("invalid proxy CA certificate"))?;
            }
        }
        let server_name = match endpoint.host().as_ip_addr() {
            Some(address) => ServerName::IpAddress(address.into()),
            None => ServerName::try_from(endpoint.host().to_string())
                .map_err(|_| UpstreamProxyConfigError("invalid proxy TLS server name"))?,
        };
        let mut tls = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        // This connector only speaks HTTP/1.1 CONNECT, even if the proxy also supports h2.
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self::Https {
            config: Arc::new(tls),
            server_name,
        })
    }

    pub(super) async fn connect(
        &self,
        stream: TcpStream,
        deadline: Instant,
        budget: std::time::Duration,
    ) -> Result<BoxedDuplexStream, UpstreamProxyError> {
        match self {
            Self::Http => Ok(Box::new(stream)),
            Self::Https {
                config,
                server_name,
            } => {
                let stream = timeout_at(
                    deadline,
                    TlsConnector::from(config.clone()).connect(server_name.clone(), stream),
                )
                .await
                .map_err(|_| UpstreamProxyError::Timeout {
                    stage: ProxyConnectStage::TlsHandshake,
                    timeout: budget,
                })?
                .map_err(|source| UpstreamProxyError::Io {
                    stage: ProxyConnectStage::TlsHandshake,
                    source,
                })?;
                Ok(Box::new(stream))
            }
        }
    }
}
