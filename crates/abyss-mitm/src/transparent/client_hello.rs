//! TLS `ClientHello` inspection for domain-based decryption policy.
//!
//! When TLS decryption policy depends on SNI, the engine must read the client's
//! `ClientHello` before deciding between MITM interception and raw passthrough.
//! This module delegates TLS parsing to `rustls::server::Acceptor` and keeps the
//! exact raw bytes that were consumed from the client socket. Passthrough flows
//! replay those bytes to upstream before entering normal TCP relay, while MITM
//! flows continue the rustls server handshake from the accepted state.

use std::{fmt, io::Cursor, time::Duration};

use tokio::{io::AsyncReadExt as _, time};
use tokio_rustls::rustls;

use super::{BoxedDuplexStream, DuplexStream, FlowOperation, TransparentFlowError};

const DEFAULT_MAX_CLIENT_HELLO_BYTES: usize = 64 * 1024;
const CLIENT_HELLO_READ_CHUNK_BYTES: usize = 16 * 1024;

/// Reads and parses the first TLS `ClientHello` from an accepted TCP stream.
#[derive(Debug, Clone)]
pub(super) struct ClientHelloInspector {
    max_client_hello_bytes: usize,
}

/// Result of reading the first TLS `ClientHello`.
///
/// `raw_bytes` contains every byte consumed from the client socket while rustls
/// was waiting for a complete `ClientHello`. For passthrough, these bytes must
/// be written to upstream before relaying the rest of the TCP stream. For MITM,
/// `accepted` carries the rustls state required to continue the server-side TLS
/// handshake without reading the `ClientHello` a second time.
pub(super) struct InspectedClientHello {
    pub(super) stream: BoxedDuplexStream,
    pub(super) accepted: rustls::server::Accepted,
    pub(super) server_name: Option<String>,
    pub(super) raw_bytes: Box<[u8]>,
}

impl fmt::Debug for InspectedClientHello {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InspectedClientHello")
            .field("server_name", &self.server_name)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish_non_exhaustive()
    }
}

impl Default for ClientHelloInspector {
    fn default() -> Self {
        Self {
            max_client_hello_bytes: DEFAULT_MAX_CLIENT_HELLO_BYTES,
        }
    }
}

impl ClientHelloInspector {
    /// Reads the first TLS `ClientHello` and returns the stream plus rustls state.
    ///
    /// The read is intentionally consuming. Any caller that chooses passthrough
    /// after this point must replay `InspectedClientHello::raw_bytes` upstream
    /// before relaying the remaining socket bytes.
    pub(super) async fn read_client_hello<S>(
        &self,
        stream: S,
        read_timeout: Duration,
    ) -> Result<InspectedClientHello, TransparentFlowError>
    where
        S: DuplexStream + 'static,
    {
        time::timeout(read_timeout, self.read_client_hello_inner(Box::new(stream)))
            .await
            .map_err(|_elapsed| TransparentFlowError::Timeout {
                operation: FlowOperation::ReadAgentTlsClientHello,
                timeout: read_timeout,
            })?
    }

    async fn read_client_hello_inner(
        &self,
        mut stream: BoxedDuplexStream,
    ) -> Result<InspectedClientHello, TransparentFlowError> {
        let mut acceptor = rustls::server::Acceptor::default();
        let mut raw_bytes = Vec::new();

        loop {
            if raw_bytes.len() >= self.max_client_hello_bytes {
                return Err(TransparentFlowError::TlsClientHelloTooLarge {
                    size: raw_bytes.len(),
                    limit: self.max_client_hello_bytes,
                });
            }

            let remaining_limit = self
                .max_client_hello_bytes
                .checked_sub(raw_bytes.len())
                .ok_or(TransparentFlowError::ByteCountOverflow)?;
            let mut chunk = vec![0_u8; CLIENT_HELLO_READ_CHUNK_BYTES.min(remaining_limit)];
            let read_len =
                stream
                    .read(&mut chunk)
                    .await
                    .map_err(|source| TransparentFlowError::Io {
                        operation: FlowOperation::ReadAgentTlsClientHello,
                        source,
                    })?;
            if read_len == 0 {
                return Err(TransparentFlowError::ClientClosedBeforeProtocol);
            }

            raw_bytes.extend_from_slice(&chunk[..read_len]);
            feed_acceptor(&mut acceptor, &chunk[..read_len])?;
            if let Some(accepted) = accept_client_hello(&mut acceptor)? {
                let server_name = accepted.client_hello().server_name().map(ToOwned::to_owned);
                return Ok(InspectedClientHello {
                    stream,
                    accepted,
                    server_name,
                    raw_bytes: raw_bytes.into_boxed_slice(),
                });
            }
        }
    }
}

fn feed_acceptor(
    acceptor: &mut rustls::server::Acceptor,
    bytes: &[u8],
) -> Result<(), TransparentFlowError> {
    let mut cursor = Cursor::new(bytes);
    while usize::try_from(cursor.position()).map_err(|_error| {
        TransparentFlowError::MalformedTlsClientHello("ClientHello cursor offset overflowed")
    })? < bytes.len()
    {
        let read_len =
            acceptor
                .read_tls(&mut cursor)
                .map_err(|source| TransparentFlowError::Io {
                    operation: FlowOperation::ReadAgentTlsClientHello,
                    source,
                })?;
        if read_len == 0 {
            return Err(TransparentFlowError::MalformedTlsClientHello(
                "rustls did not consume ClientHello bytes",
            ));
        }
    }
    Ok(())
}

fn accept_client_hello(
    acceptor: &mut rustls::server::Acceptor,
) -> Result<Option<rustls::server::Accepted>, TransparentFlowError> {
    acceptor
        .accept()
        .map_err(|(error, _alert)| TransparentFlowError::Io {
            operation: FlowOperation::ReadAgentTlsClientHello,
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        })
}

#[cfg(test)]
mod tests {
    use std::{sync::Arc, time::Duration};

    use tokio::{net::TcpListener, task::JoinHandle};
    use tokio_rustls::{
        TlsConnector,
        rustls::{ClientConfig, RootCertStore, pki_types::ServerName},
    };

    use super::{ClientHelloInspector, feed_acceptor};

    #[tokio::test]
    async fn reads_sni_with_rustls_acceptor() {
        let server_name = "api.openai.com";
        let (client, server) = connected_pair().await;
        let client_task = spawn_tls_client_hello(client, server_name);

        let inspected = ClientHelloInspector::default()
            .read_client_hello(server, Duration::from_secs(1))
            .await
            .expect("ClientHello should be readable");

        assert_eq!(inspected.server_name.as_deref(), Some(server_name));
        assert!(
            !inspected.raw_bytes.is_empty(),
            "inspector should preserve raw ClientHello bytes"
        );
        client_task.abort();
    }

    #[tokio::test]
    async fn preserved_raw_bytes_can_be_reparsed_by_rustls() {
        let (client, server) = connected_pair().await;
        let client_task = spawn_tls_client_hello(client, "chatgpt.com");
        let inspected = ClientHelloInspector::default()
            .read_client_hello(server, Duration::from_secs(1))
            .await
            .expect("ClientHello should be readable");

        let mut acceptor = tokio_rustls::rustls::server::Acceptor::default();
        feed_acceptor(&mut acceptor, &inspected.raw_bytes)
            .expect("preserved raw bytes should still be valid TLS");
        let accepted = acceptor
            .accept()
            .expect("preserved ClientHello should parse")
            .expect("preserved bytes should contain a full ClientHello");

        assert_eq!(
            accepted.client_hello().server_name(),
            Some("chatgpt.com"),
            "raw bytes should replay the original ClientHello exactly"
        );
        client_task.abort();
    }

    #[tokio::test]
    async fn enforces_client_hello_size_limit() {
        let (client, server) = connected_pair().await;
        let client_task = spawn_tls_client_hello(client, "api.openai.com");
        let inspector = ClientHelloInspector {
            max_client_hello_bytes: 1,
        };

        let error = inspector
            .read_client_hello(server, Duration::from_secs(1))
            .await
            .expect_err("tiny limit should reject the ClientHello");

        assert!(
            matches!(
                error,
                crate::transparent::TransparentFlowError::TlsClientHelloTooLarge { .. }
            ),
            "unexpected error: {error:?}"
        );
        client_task.abort();
    }

    async fn connected_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let listener_addr = listener
            .local_addr()
            .expect("test listener should expose its address");
        let client = tokio::net::TcpStream::connect(listener_addr);
        let server = listener.accept();
        let (client, server) = tokio::join!(client, server);
        (
            client.expect("test client should connect"),
            server.expect("test server should accept").0,
        )
    }

    fn spawn_tls_client_hello(
        client: tokio::net::TcpStream,
        server_name: &'static str,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let _result = TlsConnector::from(test_client_config())
                .connect(
                    ServerName::try_from(server_name)
                        .expect("test server name should be valid")
                        .to_owned(),
                    client,
                )
                .await;
        })
    }

    fn test_client_config() -> Arc<ClientConfig> {
        crate::install_default_crypto_provider();
        let root_store = RootCertStore::empty();
        Arc::new(
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
    }
}
