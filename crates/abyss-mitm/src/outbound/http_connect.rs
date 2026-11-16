//! Bounded HTTP CONNECT framing and proxy-only Basic authorization.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::{
    UpstreamProxyError, authentication::ProxyAuthorization, config::ProxyCredentials, handshake_io,
};
use crate::{BoxedDuplexStream, TargetAuthority};

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

#[derive(Clone)]
pub(super) struct HttpConnectHandshake {
    authorization: Option<ProxyAuthorization>,
}

impl HttpConnectHandshake {
    pub(super) fn new(credentials: Option<&ProxyCredentials>) -> Self {
        Self {
            authorization: credentials.map(ProxyAuthorization::new),
        }
    }

    pub(super) async fn handshake(
        &self,
        stream: &mut BoxedDuplexStream,
        target: &TargetAuthority,
    ) -> Result<Vec<u8>, UpstreamProxyError> {
        let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(authorization) = &self.authorization {
            authorization.append_to(&mut request);
        }
        request.push_str("\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(handshake_io)?;
        stream.flush().await.map_err(handshake_io)?;
        let mut buffer = Vec::new();
        let mut informational = 0_usize;
        loop {
            let mut headers = [httparse::EMPTY_HEADER; MAX_HEADERS];
            let mut response = httparse::Response::new(&mut headers);
            if let httparse::Status::Complete(length) =
                response
                    .parse(&buffer)
                    .map_err(|_error| UpstreamProxyError::Protocol {
                        reason: "malformed or excessive response headers",
                    })?
            {
                if length > MAX_HEADER_BYTES {
                    return Err(UpstreamProxyError::Protocol {
                        reason: "response headers exceed 16 KiB",
                    });
                }
                let status = response.code.ok_or(UpstreamProxyError::Protocol {
                    reason: "missing status code",
                })?;
                if (200..300).contains(&status) {
                    return Ok(buffer.split_off(length));
                }
                if (100..200).contains(&status)
                    && status != 101
                    && informational < MAX_INFORMATIONAL_RESPONSES
                {
                    informational = informational.saturating_add(1);
                    buffer.drain(..length);
                    continue;
                }
                if (100..200).contains(&status) {
                    return Err(UpstreamProxyError::Protocol {
                        reason: "unsupported or excessive informational responses",
                    });
                }
                return Err(UpstreamProxyError::Rejected { status });
            }
            if buffer.len() >= MAX_HEADER_BYTES {
                return Err(UpstreamProxyError::Protocol {
                    reason: "response headers exceed 16 KiB",
                });
            }
            let mut chunk = [0; 2048];
            let count = stream.read(&mut chunk).await.map_err(handshake_io)?;
            if count == 0 {
                return Err(UpstreamProxyError::Protocol {
                    reason: "EOF before CONNECT response headers",
                });
            }
            buffer.extend_from_slice(&chunk[..count]);
        }
    }
}
