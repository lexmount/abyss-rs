//! HTTP CONNECT negotiation relayed between an Agent and its original proxy.
//!
//! Owns protocol framing only: callers supply both connected byte streams. No
//! sockets, DNS, platform APIs, TLS termination, or content hooks live here.

mod response;
#[cfg(test)]
mod tests;

use std::{io, time::Duration};

use thiserror::Error;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    time,
};

use crate::transparent::PrefixedDuplexStream;
use crate::{BoxedDuplexStream, ExplicitRequestDecoder, ExplicitRequestError, TargetAuthority};
use response::ProxyResponse;

const MAX_HEAD_BYTES: usize = 16 * 1024;
const MAX_NEGOTIATIONS: usize = 8;
const MAX_INFORMATIONAL: usize = 8;

/// Result of a non-destructive CONNECT method probe.
#[expect(
    clippy::exhaustive_enums,
    reason = "The probe always returns the restored stream on one of two paths."
)]
pub enum ConnectProbe {
    /// All observed bytes are restored for the existing HTTP/TLS pipeline.
    Other(BoxedDuplexStream),
    /// The stream starts with CONNECT; full validation follows during relay.
    Connect(BoxedDuplexStream),
}

impl ConnectProbe {
    /// Checks only the method prefix, preserving every byte on both paths.
    ///
    /// # Errors
    /// Returns an I/O error or a bounded protocol-detection timeout.
    pub async fn read(
        mut stream: BoxedDuplexStream,
        timeout: Duration,
    ) -> Result<Self, ConnectRelayError> {
        let mut prefix = Vec::with_capacity(8);
        let matched = time::timeout(timeout, async {
            for expected in b"CONNECT " {
                let mut byte = [0];
                if stream.read(&mut byte).await? == 0 {
                    return Ok::<_, io::Error>(false);
                }
                prefix.push(byte[0]);
                if byte[0] != *expected {
                    return Ok(false);
                }
            }
            Ok(true)
        })
        .await
        .map_err(|_| ConnectRelayError::Timeout)??;
        let stream = PrefixedDuplexStream::new(prefix.into_boxed_slice(), stream).boxed();
        Ok(if matched {
            Self::Connect(stream)
        } else {
            Self::Other(stream)
        })
    }
}

/// Result of forwarding the proxy negotiation, before any application parsing.
#[expect(
    clippy::exhaustive_enums,
    reason = "Negotiation either establishes a tunnel or closes the pair."
)]
pub enum ConnectRelayOutcome {
    /// Both streams are positioned at the first byte inside the tunnel.
    Established {
        /// Agent-side stream, including any optimistic tunnel prefix.
        client: BoxedDuplexStream,
        /// Original proxy stream, including any buffered tunnel prefix.
        upstream: BoxedDuplexStream,
        /// Agent-requested authority; its DNS resolution belongs to the proxy.
        target: TargetAuthority,
    },
    /// A complete non-success response ended the proxy connection.
    Closed,
}

/// Bounded handshake relay. Credentials are forwarded only to the supplied peer.
pub struct HttpConnectRelay {
    timeout: Duration,
}

impl Default for HttpConnectRelay {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

impl HttpConnectRelay {
    /// Creates a relay with one budget covering all authentication rounds.
    #[must_use]
    pub const fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    /// Relays negotiation without synthesizing success or replaying requests.
    ///
    /// # Errors
    /// Returns bounded framing, validation, timeout, or transport errors. Errors
    /// never contain proxy response bodies or authentication header values.
    pub async fn relay(
        &self,
        client: BoxedDuplexStream,
        upstream: BoxedDuplexStream,
    ) -> Result<ConnectRelayOutcome, ConnectRelayError> {
        let mut client = BufReader::new(client);
        let mut upstream = BufReader::new(upstream);
        let result = time::timeout(self.timeout, Self::negotiate(&mut client, &mut upstream))
            .await
            .unwrap_or(Err(ConnectRelayError::Timeout));
        if let Ok(Some(target)) = result {
            return Ok(ConnectRelayOutcome::Established {
                client: unbuffer(client),
                upstream: unbuffer(upstream),
                target,
            });
        }
        // Framed NE streams need a directional close frame, including on error.
        // Bound cleanup so a stalled peer cannot extend the handshake forever.
        let closed = time::timeout(Duration::from_secs(1), async {
            client.shutdown().await?;
            upstream.shutdown().await
        })
        .await;
        let _target = result?;
        closed.map_err(|_| ConnectRelayError::Timeout)??;
        Ok(ConnectRelayOutcome::Closed)
    }

    async fn negotiate(
        client: &mut BufReader<BoxedDuplexStream>,
        upstream: &mut BufReader<BoxedDuplexStream>,
    ) -> Result<Option<TargetAuthority>, ConnectRelayError> {
        for _ in 0..MAX_NEGOTIATIONS {
            let head = read_head(client).await?;
            let target = ExplicitRequestDecoder::connect_target(&head)?;
            // Retain the Agent's request and hop authentication verbatim. The
            // configured-upstream connector instead originates its own CONNECT.
            upstream.write_all(&head).await?;
            upstream.flush().await?;
            let mut response = None;
            for _ in 0..MAX_INFORMATIONAL {
                let head = read_head(upstream).await?;
                let parsed = ProxyResponse::parse(&head)?;
                client.write_all(&head).await?;
                client.flush().await?;
                if parsed.is_success() {
                    return Ok(Some(target));
                }
                if !parsed.is_informational() {
                    response = Some(parsed);
                    break;
                }
            }
            let response = response.ok_or(ConnectRelayError::Protocol(
                "too many informational responses",
            ))?;
            response.forward_body(upstream, client).await?;
            client.flush().await?;
            if response.closes_connection() {
                return Ok(None);
            }
            // In particular, a 407 remains a challenge from the original proxy.
            // Keep the same socket pair for connection-bound authentication.
        }
        Err(ConnectRelayError::Protocol(
            "too many CONNECT negotiation rounds",
        ))
    }
}

/// Safe diagnostic categories for handshake failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConnectRelayError {
    /// Transport failed without exposing protocol payloads.
    #[error("proxy negotiation I/O failed: {0}")]
    Io(#[from] io::Error),
    /// The Agent sent a malformed proxy request.
    #[error("invalid CONNECT request: {0}")]
    Request(#[from] ExplicitRequestError),
    /// A complete handshake exceeded its fixed time budget.
    #[error("proxy negotiation timed out")]
    Timeout,
    /// Protocol framing was invalid or exceeded a bound.
    #[error("proxy negotiation failed: {0}")]
    Protocol(&'static str),
}

async fn read_head(
    reader: &mut BufReader<BoxedDuplexStream>,
) -> Result<Vec<u8>, ConnectRelayError> {
    let mut head = Vec::new();
    loop {
        let line = read_line(reader, MAX_HEAD_BYTES.saturating_sub(head.len())).await?;
        head.extend_from_slice(&line);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
}

async fn read_line(
    reader: &mut BufReader<BoxedDuplexStream>,
    limit: usize,
) -> Result<Vec<u8>, ConnectRelayError> {
    let mut line = Vec::new();
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            return Err(ConnectRelayError::Protocol(
                "unexpected EOF during negotiation",
            ));
        }
        let count = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index.saturating_add(1));
        if count > limit.saturating_sub(line.len()) {
            return Err(ConnectRelayError::Protocol(
                "negotiation framing exceeds limit",
            ));
        }
        line.extend_from_slice(&buffer[..count]);
        reader.consume(count);
        if line.ends_with(b"\n") {
            if !line.ends_with(b"\r\n") {
                return Err(ConnectRelayError::Protocol("negotiation requires CRLF"));
            }
            return Ok(line);
        }
    }
}

fn unbuffer(reader: BufReader<BoxedDuplexStream>) -> BoxedDuplexStream {
    let prefix = reader.buffer().to_vec().into_boxed_slice();
    PrefixedDuplexStream::new(prefix, reader.into_inner()).boxed()
}
