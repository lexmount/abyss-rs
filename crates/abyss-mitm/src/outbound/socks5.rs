//! SOCKS5 TCP CONNECT framing; target resolution belongs exclusively to the proxy.

use std::{net::IpAddr, sync::Arc};

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{UpstreamProxyConfigError, UpstreamProxyError, config::ProxyCredentials, handshake_io};
use crate::{BoxedDuplexStream, TargetAuthority};

/// Prepared authentication bytes are private to the route and never formatted.
#[derive(Clone)]
pub(super) struct Socks5Handshake {
    authentication: Option<Arc<[u8]>>,
}

impl Socks5Handshake {
    pub(super) fn new(
        credentials: Option<&ProxyCredentials>,
    ) -> Result<Self, UpstreamProxyConfigError> {
        let authentication = credentials
            .map(|credentials| {
                let mut request = vec![1];
                for value in [&credentials.username, &credentials.password] {
                    let length = u8::try_from(value.len())
                        .ok()
                        .filter(|length| *length > 0)
                        .ok_or(UpstreamProxyConfigError(
                            "SOCKS5 credentials must contain 1..=255 UTF-8 bytes",
                        ))?;
                    request.push(length);
                    request.extend_from_slice(value.as_bytes());
                }
                Ok(Arc::from(request))
            })
            .transpose()?;
        Ok(Self { authentication })
    }

    pub(super) async fn negotiate(
        &self,
        stream: &mut BoxedDuplexStream,
        target: &TargetAuthority,
    ) -> Result<(), UpstreamProxyError> {
        let request = Self::connect_request(target)?;
        // Offer exactly the configured method: never downgrade supplied credentials.
        let method = if self.authentication.is_some() { 2 } else { 0 };
        stream
            .write_all(&[5, 1, method])
            .await
            .map_err(handshake_io)?;
        stream.flush().await.map_err(handshake_io)?;
        let mut reply = [0; 2];
        stream.read_exact(&mut reply).await.map_err(handshake_io)?;
        if reply[0] != 5 {
            return Err(UpstreamProxyError::Protocol {
                reason: "invalid SOCKS5 method reply version",
            });
        }
        if reply[1] != method {
            return Err(UpstreamProxyError::Authentication);
        }
        if let Some(authentication) = &self.authentication {
            stream
                .write_all(authentication)
                .await
                .map_err(handshake_io)?;
            stream.flush().await.map_err(handshake_io)?;
            stream.read_exact(&mut reply).await.map_err(handshake_io)?;
            if reply[0] != 1 {
                return Err(UpstreamProxyError::Protocol {
                    reason: "invalid SOCKS5 authentication reply version",
                });
            }
            if reply[1] != 0 {
                return Err(UpstreamProxyError::Authentication);
            }
        }
        stream.write_all(&request).await.map_err(handshake_io)?;
        stream.flush().await.map_err(handshake_io)?;
        Self::read_connect_reply(stream).await
    }

    #[expect(
        clippy::big_endian_bytes,
        reason = "SOCKS5 encodes the target port in network byte order."
    )]
    fn connect_request(target: &TargetAuthority) -> Result<Vec<u8>, UpstreamProxyError> {
        let mut request = vec![5, 1, 0];
        match target.host().as_ip_addr() {
            Some(IpAddr::V4(address)) => {
                request.push(1);
                request.extend_from_slice(&address.octets());
            }
            Some(IpAddr::V6(address)) => {
                request.push(4);
                request.extend_from_slice(&address.octets());
            }
            None => {
                let host = target
                    .host()
                    .as_dns_name()
                    .ok_or(UpstreamProxyError::Protocol {
                        reason: "unsupported SOCKS5 target host",
                    })?;
                let length = u8::try_from(host.len())
                    .ok()
                    .filter(|length| *length > 0)
                    .ok_or(UpstreamProxyError::Protocol {
                        reason: "SOCKS5 target name must contain 1..=255 bytes",
                    })?;
                request.extend_from_slice(&[3, length]);
                request.extend_from_slice(host.as_bytes());
            }
        }
        request.extend_from_slice(&target.port().to_be_bytes());
        Ok(request)
    }

    async fn read_connect_reply(stream: &mut BoxedDuplexStream) -> Result<(), UpstreamProxyError> {
        let mut header = [0; 4];
        stream.read_exact(&mut header).await.map_err(handshake_io)?;
        if header[0] != 5 || header[2] != 0 {
            return Err(UpstreamProxyError::Protocol {
                reason: "invalid SOCKS5 CONNECT reply header",
            });
        }
        if header[1] != 0 {
            return Err(UpstreamProxyError::Socks5Rejected { reply: header[1] });
        }
        let address_length = match header[3] {
            1 => 4,
            4 => 16,
            3 => {
                let length = stream.read_u8().await.map_err(handshake_io)?;
                if length == 0 {
                    return Err(UpstreamProxyError::Protocol {
                        reason: "empty SOCKS5 bound domain",
                    });
                }
                usize::from(length)
            }
            _ => {
                return Err(UpstreamProxyError::Protocol {
                    reason: "invalid SOCKS5 reply address type",
                });
            }
        };
        // The bound endpoint is informational. Consume only its bytes and port;
        // any coalesced target data must remain available to the caller.
        let mut bound = [0; 255];
        stream
            .read_exact(&mut bound[..address_length])
            .await
            .map_err(handshake_io)?;
        let mut port = [0; 2];
        stream.read_exact(&mut port).await.map_err(handshake_io)?;
        Ok(())
    }
}
