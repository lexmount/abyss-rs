//! Bounded HTTP response framing for CONNECT challenges and rejections.
//!
//! Streams error bodies without capture; successful CONNECT ignores HTTP body
//! framing and leaves all remaining bytes for the established tunnel.

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader};

use super::{ConnectRelayError, MAX_HEAD_BYTES, read_line};
use crate::BoxedDuplexStream;

pub(super) struct ProxyResponse {
    status: u16,
    close: bool,
    body: ResponseBody,
}

enum ResponseBody {
    Empty,
    Length(u64),
    Chunked,
    UntilEof,
}

impl ProxyResponse {
    pub(super) fn parse(head: &[u8]) -> Result<Self, ConnectRelayError> {
        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        if response
            .parse(head)
            .map_err(|_| ConnectRelayError::Protocol("invalid proxy response head"))?
            != httparse::Status::Complete(head.len())
        {
            return Err(ConnectRelayError::Protocol("incomplete proxy response"));
        }
        let status = response
            .code
            .ok_or(ConnectRelayError::Protocol("missing proxy status"))?;
        if !(100..600).contains(&status) {
            return Err(ConnectRelayError::Protocol("invalid proxy response status"));
        }
        if status == 101 {
            return Err(ConnectRelayError::Protocol(
                "CONNECT cannot upgrade with status 101",
            ));
        }
        if (100..300).contains(&status) {
            return Ok(Self {
                status,
                close: false,
                body: ResponseBody::Empty,
            });
        }
        let mut length = None;
        let mut chunked = false;
        let mut close = response.version != Some(1);
        for header in response.headers.iter() {
            if header.name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err(ConnectRelayError::Protocol(
                        "duplicate proxy content length",
                    ));
                }
                let value = std::str::from_utf8(header.value)
                    .map_err(|_| ConnectRelayError::Protocol("invalid proxy content length"))?
                    .trim();
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err(ConnectRelayError::Protocol("invalid proxy content length"));
                }
                length =
                    Some(value.parse::<u64>().map_err(|_| {
                        ConnectRelayError::Protocol("invalid proxy content length")
                    })?);
            } else if header.name.eq_ignore_ascii_case("transfer-encoding") {
                if chunked || !header.value.eq_ignore_ascii_case(b"chunked") {
                    return Err(ConnectRelayError::Protocol(
                        "unsupported proxy transfer encoding",
                    ));
                }
                chunked = true;
            } else if header.name.eq_ignore_ascii_case("connection") {
                close |= header
                    .value
                    .split(|byte| *byte == b',')
                    .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"close"));
            }
        }
        if chunked && length.is_some() {
            return Err(ConnectRelayError::Protocol(
                "ambiguous proxy response framing",
            ));
        }
        let body = if status == 304 {
            ResponseBody::Empty
        } else if chunked {
            ResponseBody::Chunked
        } else if let Some(length) = length {
            ResponseBody::Length(length)
        } else {
            close = true;
            ResponseBody::UntilEof
        };
        Ok(Self {
            status,
            close,
            body,
        })
    }

    pub(super) const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
    pub(super) const fn is_informational(&self) -> bool {
        self.status >= 100 && self.status < 200
    }
    pub(super) const fn closes_connection(&self) -> bool {
        self.close
    }

    pub(super) async fn forward_body(
        &self,
        upstream: &mut BufReader<BoxedDuplexStream>,
        client: &mut BufReader<BoxedDuplexStream>,
    ) -> Result<(), ConnectRelayError> {
        match self.body {
            ResponseBody::Empty => {}
            ResponseBody::Length(length) => copy_exact(upstream, client, length).await?,
            ResponseBody::UntilEof => {
                tokio::io::copy(upstream, client).await?;
            }
            ResponseBody::Chunked => forward_chunks(upstream, client).await?,
        }
        Ok(())
    }
}

async fn copy_exact(
    upstream: &mut BufReader<BoxedDuplexStream>,
    client: &mut BufReader<BoxedDuplexStream>,
    length: u64,
) -> Result<(), ConnectRelayError> {
    if tokio::io::copy(&mut upstream.take(length), client).await? != length {
        return Err(ConnectRelayError::Protocol("truncated proxy response body"));
    }
    Ok(())
}

async fn forward_chunks(
    upstream: &mut BufReader<BoxedDuplexStream>,
    client: &mut BufReader<BoxedDuplexStream>,
) -> Result<(), ConnectRelayError> {
    loop {
        let line = read_line(upstream, MAX_HEAD_BYTES).await?;
        let raw_size = line
            .split(|byte| *byte == b';' || *byte == b'\r')
            .next()
            .unwrap_or_default();
        if raw_size.is_empty() || !raw_size.iter().all(u8::is_ascii_hexdigit) {
            return Err(ConnectRelayError::Protocol("invalid proxy chunk size"));
        }
        let size = std::str::from_utf8(raw_size)
            .ok()
            .and_then(|size| u64::from_str_radix(size, 16).ok())
            .ok_or(ConnectRelayError::Protocol("invalid proxy chunk size"))?;
        client.write_all(&line).await?;
        if size == 0 {
            let mut remaining = MAX_HEAD_BYTES;
            loop {
                let trailer = read_line(upstream, remaining).await?;
                remaining = remaining.saturating_sub(trailer.len());
                client.write_all(&trailer).await?;
                if trailer == b"\r\n" {
                    return Ok(());
                }
            }
        }
        copy_exact(upstream, client, size).await?;
        let mut terminator = [0; 2];
        upstream.read_exact(&mut terminator).await?;
        if terminator != *b"\r\n" {
            return Err(ConnectRelayError::Protocol(
                "invalid proxy chunk terminator",
            ));
        }
        client.write_all(&terminator).await?;
    }
}
