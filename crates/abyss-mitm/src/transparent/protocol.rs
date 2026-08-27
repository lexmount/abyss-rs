//! Initial protocol detection for transparent TCP flows.
//!
//! The broker receives all redirected traffic as raw TCP. Before a flow can be
//! decoded, the MITM pipeline peeks a few bytes without consuming them and
//! decides whether the client is speaking plain HTTP/1 or starting TLS.

use std::{net::SocketAddr, time::Duration};

use tokio::{io::AsyncReadExt as _, time};

use super::{AcceptedTcpFlow, FlowOperation, TransparentFlowError};

const MAX_PROTOCOL_PREFIX_BYTES: usize = 64;
const TLS_HANDSHAKE_CONTENT_TYPE: u8 = 0x16;
const TLS_MAJOR_VERSION: u8 = 0x03;

#[derive(Debug)]
pub(super) enum DetectedProtocol {
    PlainHttp,
    Tls,
}

impl DetectedProtocol {
    pub(super) async fn detect(
        mut flow: AcceptedTcpFlow,
        detection_timeout: Duration,
    ) -> Result<DetectedFlow, TransparentFlowError> {
        let mut prefix = Vec::with_capacity(MAX_PROTOCOL_PREFIX_BYTES);
        let protocol = time::timeout(detection_timeout, async {
            loop {
                match ProtocolPrefix::classify(&prefix) {
                    ProtocolPrefix::Detected(protocol) => return Ok(protocol),
                    ProtocolPrefix::Unsupported => {
                        return Err(TransparentFlowError::UnsupportedProtocol);
                    }
                    ProtocolPrefix::Incomplete => {}
                }
                if prefix.len() == MAX_PROTOCOL_PREFIX_BYTES {
                    return Err(TransparentFlowError::UnsupportedProtocol);
                }

                let remaining = MAX_PROTOCOL_PREFIX_BYTES.saturating_sub(prefix.len());
                let mut chunk = [0_u8; 16];
                let read_capacity = remaining.min(chunk.len());
                let read_len = flow
                    .stream
                    .read(&mut chunk[..read_capacity])
                    .await
                    .map_err(|source| TransparentFlowError::Io {
                        operation: FlowOperation::ReadAgentProtocol,
                        source,
                    })?;
                if read_len == 0 {
                    return Err(TransparentFlowError::ClientClosedBeforeProtocol);
                }
                prefix.extend_from_slice(&chunk[..read_len]);
            }
        })
        .await
        .map_err(|_elapsed| TransparentFlowError::Timeout {
            operation: FlowOperation::ReadAgentProtocol,
            timeout: detection_timeout,
        })??;

        Ok(DetectedFlow::new(
            protocol,
            flow.with_read_prefix(prefix.into_boxed_slice()),
        ))
    }
}

enum ProtocolPrefix {
    Detected(DetectedProtocol),
    Incomplete,
    Unsupported,
}

impl ProtocolPrefix {
    fn classify(prefix: &[u8]) -> Self {
        let Some(first) = prefix.first() else {
            return Self::Incomplete;
        };
        if *first == TLS_HANDSHAKE_CONTENT_TYPE {
            return match prefix.get(1) {
                Some(major_version) if *major_version == TLS_MAJOR_VERSION => {
                    Self::Detected(DetectedProtocol::Tls)
                }
                Some(_) => Self::Unsupported,
                None => Self::Incomplete,
            };
        }

        for (index, byte) in prefix.iter().copied().enumerate() {
            if byte == b' ' {
                return if index > 0 {
                    Self::Detected(DetectedProtocol::PlainHttp)
                } else {
                    Self::Unsupported
                };
            }
            if !is_http_token_byte(byte) {
                return Self::Unsupported;
            }
        }
        Self::Incomplete
    }
}

const fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub(super) struct DetectedFlow {
    protocol: DetectedProtocol,
    flow: AcceptedTcpFlow,
}

impl DetectedFlow {
    #[must_use]
    const fn new(protocol: DetectedProtocol, flow: AcceptedTcpFlow) -> Self {
        Self { protocol, flow }
    }

    #[must_use]
    pub(super) const fn protocol(&self) -> &DetectedProtocol {
        &self.protocol
    }

    #[must_use]
    pub(super) const fn peer_addr(&self) -> Option<SocketAddr> {
        self.flow.peer_addr
    }

    #[must_use]
    pub(super) const fn local_addr(&self) -> Option<SocketAddr> {
        self.flow.local_addr
    }

    #[must_use]
    pub(super) const fn original_destination(&self) -> &super::OriginalDestination {
        &self.flow.original_destination
    }

    #[must_use]
    pub(super) fn into_parts(self) -> (DetectedProtocol, AcceptedTcpFlow) {
        (self.protocol, self.flow)
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, time::Duration};

    use tokio::{
        io::{AsyncWriteExt as _, duplex},
        time::sleep,
    };

    use super::{DetectedProtocol, ProtocolPrefix};
    use crate::transparent::{AcceptedTcpFlow, MitmTimeouts, OriginalDestination};

    #[test]
    fn accepts_extension_http_methods() {
        assert!(matches!(
            ProtocolPrefix::classify(b"PROPFIND "),
            ProtocolPrefix::Detected(DetectedProtocol::PlainHttp)
        ));
    }

    #[test]
    fn waits_for_fragmented_tls_prefix() {
        assert!(matches!(
            ProtocolPrefix::classify(&[0x16]),
            ProtocolPrefix::Incomplete
        ));
        assert!(matches!(
            ProtocolPrefix::classify(&[0x16, 0x03]),
            ProtocolPrefix::Detected(DetectedProtocol::Tls)
        ));
    }

    #[tokio::test]
    async fn detection_accumulates_fragmented_http_method() {
        let (mut client, server) = duplex(1024);
        let flow = AcceptedTcpFlow::new(
            server,
            SocketAddr::from(([127, 0, 0, 1], 41000)),
            SocketAddr::from(([127, 0, 0, 1], 41001)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 80))),
        );
        let detection = tokio::spawn(async move {
            DetectedProtocol::detect(flow, MitmTimeouts::default().protocol_detection).await
        });

        client
            .write_all(b"PRO")
            .await
            .expect("first HTTP method fragment should write");
        sleep(Duration::from_millis(10)).await;
        client
            .write_all(b"PFIND / HTTP/1.1\r\nHost: example.test\r\n\r\n")
            .await
            .expect("remaining HTTP request should write");

        let detected = detection
            .await
            .expect("detection task should join")
            .expect("fragmented HTTP method should detect");
        assert!(matches!(detected.protocol(), DetectedProtocol::PlainHttp));
    }
}
