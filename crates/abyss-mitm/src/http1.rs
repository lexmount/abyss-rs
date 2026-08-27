//! HTTP/1 head decoding for transparent MITM flows.
//!
//! The transparent pipeline decodes the first request head and the first
//! response head, then streams the remaining bytes. Each decoder preserves all
//! bytes consumed while looking for the header terminator because a single read
//! may also contain early body bytes.

use http::{
    Method, Request, Response, StatusCode, Uri, Version,
    header::{HeaderName, HeaderValue},
};
use std::time::Duration;
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    time,
};

const HEADER_READ_CHUNK_BYTES: usize = 1024;

/// Maximum HTTP/1 request or response head size accepted by the decoder.
pub const MAX_HTTP1_HEADER_BYTES: usize = 64 * 1024;

/// Bytes consumed while decoding an HTTP/1 head.
#[derive(Debug, Clone)]
pub struct Http1HeadBuffer {
    bytes: Box<[u8]>,
    head_len: usize,
}

/// A client stream that has not yet been decoded.
#[derive(Debug)]
pub struct Http1ClientStream<S> {
    stream: S,
}

/// A client stream after its first HTTP/1 request head has been decoded.
#[derive(Debug)]
pub struct DecodedHttp1Request<S> {
    stream: S,
    request_head: Request<()>,
    head_buffer: Http1HeadBuffer,
}

/// An upstream stream that has not yet had its first response decoded.
#[derive(Debug)]
pub struct Http1UpstreamStream<S> {
    stream: S,
}

/// An upstream stream after its first HTTP/1 response head has been decoded.
#[derive(Debug)]
pub struct DecodedHttp1Response<S> {
    stream: S,
    response_head: Response<()>,
    head_buffer: Http1HeadBuffer,
}

/// Errors returned while decoding the first HTTP/1 head.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Http1Error {
    /// The peer closed the connection before a full request head was read.
    #[error("client closed before sending a complete HTTP/1 request head")]
    IncompleteRequest,
    /// The peer closed the connection before a full response head was read.
    #[error("upstream closed before sending a complete HTTP/1 response head")]
    IncompleteResponse,
    /// The HTTP/1 head exceeded [`MAX_HTTP1_HEADER_BYTES`].
    #[error("HTTP/1 head exceeded {MAX_HTTP1_HEADER_BYTES} bytes")]
    HeaderTooLarge,
    /// The HTTP/1 body exceeded the configured capture limit.
    #[error("HTTP/1 body exceeded {limit} bytes")]
    BodyTooLarge {
        /// Configured body capture limit.
        limit: usize,
    },
    /// The HTTP/1 body framing is malformed.
    #[error("invalid HTTP/1 body: {0}")]
    InvalidBody(&'static str),
    /// The HTTP/1 body framing is not supported by the first exchange relay.
    #[error("unsupported HTTP/1 body framing: {0}")]
    UnsupportedBody(&'static str),
    /// Reading the first request head exceeded its timeout budget.
    #[error("HTTP/1 request head timed out after {timeout:?}")]
    RequestHeadTimeout {
        /// Configured timeout budget.
        timeout: Duration,
    },
    /// Reading the first response head exceeded its timeout budget.
    #[error("HTTP/1 response head timed out after {timeout:?}")]
    ResponseHeadTimeout {
        /// Configured timeout budget.
        timeout: Duration,
    },
    /// The parser rejected the request or response head syntax.
    #[error("failed to parse HTTP/1 head")]
    Parse(#[from] httparse::Error),
    /// Required request-line metadata was missing.
    #[error("invalid HTTP/1 request: {0}")]
    InvalidRequest(&'static str),
    /// Required response-line metadata was missing.
    #[error("invalid HTTP/1 response: {0}")]
    InvalidResponse(&'static str),
    /// The HTTP method token cannot be represented by the `http` crate.
    #[error("invalid HTTP method")]
    InvalidMethod(#[from] http::method::InvalidMethod),
    /// The HTTP request target cannot be represented as a URI.
    #[error("invalid HTTP request URI")]
    InvalidUri(#[from] http::uri::InvalidUri),
    /// The HTTP status code cannot be represented by the `http` crate.
    #[error("invalid HTTP status code")]
    InvalidStatusCode(#[from] http::status::InvalidStatusCode),
    /// A header name cannot be represented by the `http` crate.
    #[error("invalid HTTP header name")]
    InvalidHeaderName(#[from] http::header::InvalidHeaderName),
    /// A header value cannot be represented by the `http` crate.
    #[error("invalid HTTP header value")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    /// The structured HTTP request or response could not be built.
    #[error("failed to build structured HTTP message")]
    BuildMessage(#[from] http::Error),
    /// An I/O operation failed.
    #[error("HTTP/1 I/O error: {source}")]
    Io {
        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },
}

impl Http1HeadBuffer {
    fn new(bytes: Vec<u8>, head_len: usize) -> Self {
        Self {
            bytes: bytes.into_boxed_slice(),
            head_len,
        }
    }

    /// Returns only the HTTP/1 head bytes.
    #[must_use]
    pub fn head_bytes(&self) -> &[u8] {
        &self.bytes[..self.head_len]
    }

    /// Returns bytes read after the HTTP/1 head terminator.
    #[must_use]
    pub fn buffered_body(&self) -> &[u8] {
        &self.bytes[self.head_len..]
    }
}

impl<S> Http1ClientStream<S> {
    /// Wraps a raw stream as an undecoded HTTP/1 client stream.
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Reads and parses the first HTTP/1 request head with a wall-clock budget.
    ///
    /// # Errors
    ///
    /// Returns an error when the timeout expires, the request is incomplete,
    /// malformed, too large, or the underlying stream fails.
    pub async fn decode_request_head_with_timeout(
        self,
        request_head_timeout: Duration,
    ) -> Result<DecodedHttp1Request<S>, Http1Error>
    where
        S: AsyncRead + Unpin,
    {
        time::timeout(request_head_timeout, self.decode_request_head_inner())
            .await
            .map_err(|_elapsed| Http1Error::RequestHeadTimeout {
                timeout: request_head_timeout,
            })?
    }

    async fn decode_request_head_inner(mut self) -> Result<DecodedHttp1Request<S>, Http1Error>
    where
        S: AsyncRead + Unpin,
    {
        let (request_head, head_buffer) = read_http1_head(
            &mut self.stream,
            parse_request_head,
            Http1Error::IncompleteRequest,
        )
        .await?;

        Ok(DecodedHttp1Request {
            stream: self.stream,
            request_head,
            head_buffer,
        })
    }
}

impl<S> DecodedHttp1Request<S> {
    /// Splits the decoded request back into transport, metadata, and bytes
    /// consumed while decoding the request head.
    #[must_use]
    pub fn into_parts(self) -> (S, Request<()>, Http1HeadBuffer) {
        (self.stream, self.request_head, self.head_buffer)
    }
}

impl<S> Http1UpstreamStream<S> {
    /// Wraps a raw stream as an undecoded HTTP/1 upstream stream.
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Reads and parses the first HTTP/1 response head with a wall-clock budget.
    ///
    /// # Errors
    ///
    /// Returns an error when the timeout expires, the response is incomplete,
    /// malformed, too large, or the underlying stream fails.
    pub async fn decode_response_head_with_timeout(
        self,
        response_head_timeout: Duration,
    ) -> Result<DecodedHttp1Response<S>, Http1Error>
    where
        S: AsyncRead + Unpin,
    {
        time::timeout(response_head_timeout, self.decode_response_head_inner())
            .await
            .map_err(|_elapsed| Http1Error::ResponseHeadTimeout {
                timeout: response_head_timeout,
            })?
    }

    async fn decode_response_head_inner(mut self) -> Result<DecodedHttp1Response<S>, Http1Error>
    where
        S: AsyncRead + Unpin,
    {
        let (response_head, head_buffer) = read_http1_head(
            &mut self.stream,
            parse_response_head,
            Http1Error::IncompleteResponse,
        )
        .await?;

        Ok(DecodedHttp1Response {
            stream: self.stream,
            response_head,
            head_buffer,
        })
    }
}

impl<S> DecodedHttp1Response<S> {
    /// Splits the decoded response back into transport, metadata, and bytes
    /// consumed while decoding the response head.
    #[must_use]
    pub fn into_parts(self) -> (S, Response<()>, Http1HeadBuffer) {
        (self.stream, self.response_head, self.head_buffer)
    }
}

async fn read_http1_head<S, T, P>(
    stream: &mut S,
    mut parse_head: P,
    incomplete_error: Http1Error,
) -> Result<(T, Http1HeadBuffer), Http1Error>
where
    S: AsyncRead + Unpin,
    P: FnMut(&[u8]) -> Result<Option<(T, usize)>, Http1Error>,
{
    let mut buffer = Vec::with_capacity(HEADER_READ_CHUNK_BYTES);
    loop {
        let mut chunk = [0_u8; HEADER_READ_CHUNK_BYTES];
        let read_len = stream
            .read(&mut chunk)
            .await
            .map_err(|source| Http1Error::Io { source })?;
        if read_len == 0 {
            return Err(incomplete_error);
        }

        buffer.extend_from_slice(&chunk[..read_len]);
        if let Some((head, head_len)) = parse_head(&buffer)? {
            debug_assert!(
                head_len <= buffer.len(),
                "parser head length should be within the decoded buffer"
            );
            return Ok((head, Http1HeadBuffer::new(buffer, head_len)));
        }
        if buffer.len() >= MAX_HTTP1_HEADER_BYTES {
            return Err(Http1Error::HeaderTooLarge);
        }
    }
}

fn parse_request_head(buffer: &[u8]) -> Result<Option<(Request<()>, usize)>, Http1Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut request = httparse::Request::new(&mut headers);
    let head_len = match request.parse(buffer)? {
        httparse::Status::Complete(head_len) => head_len,
        httparse::Status::Partial => return Ok(None),
    };

    let method = Method::from_bytes(
        request
            .method
            .ok_or(Http1Error::InvalidRequest("missing method"))?
            .as_bytes(),
    )?;
    let uri = Uri::try_from(
        request
            .path
            .ok_or(Http1Error::InvalidRequest("missing request target"))?,
    )?;
    let version = http_version_from_httparse(
        request
            .version
            .ok_or(Http1Error::InvalidRequest("missing HTTP version"))?,
    )?;

    let mut structured_request = Request::builder().method(method).uri(uri).body(())?;
    *structured_request.version_mut() = version;
    append_headers(structured_request.headers_mut(), request.headers)?;

    Ok(Some((structured_request, head_len)))
}

fn parse_response_head(buffer: &[u8]) -> Result<Option<(Response<()>, usize)>, Http1Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    let head_len = match response.parse(buffer)? {
        httparse::Status::Complete(head_len) => head_len,
        httparse::Status::Partial => return Ok(None),
    };

    let version = http_version_from_httparse(
        response
            .version
            .ok_or(Http1Error::InvalidResponse("missing HTTP version"))?,
    )?;
    let status = StatusCode::from_u16(
        response
            .code
            .ok_or(Http1Error::InvalidResponse("missing status code"))?,
    )?;

    let mut structured_response = Response::builder().status(status).body(())?;
    *structured_response.version_mut() = version;
    append_headers(structured_response.headers_mut(), response.headers)?;

    Ok(Some((structured_response, head_len)))
}

const fn http_version_from_httparse(version: u8) -> Result<Version, Http1Error> {
    match version {
        0 => Ok(Version::HTTP_10),
        1 => Ok(Version::HTTP_11),
        _unsupported => Err(Http1Error::InvalidRequest("unsupported HTTP version")),
    }
}

fn append_headers(
    headers: &mut http::HeaderMap,
    parsed_headers: &[httparse::Header<'_>],
) -> Result<(), Http1Error> {
    for header in parsed_headers {
        headers.append(
            HeaderName::from_bytes(header.name.as_bytes())?,
            HeaderValue::from_bytes(header.value)?,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use http::{Method, StatusCode, header::HOST};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt as _;

    use super::{Http1ClientStream, Http1UpstreamStream, MAX_HTTP1_HEADER_BYTES};

    #[tokio::test]
    async fn decodes_first_request_head_and_preserves_buffered_body() {
        let (mut client, server) = tokio::io::duplex(4096);
        client
            .write_all(b"GET /v1/models HTTP/1.1\r\nHost: example.test\r\n\r\nbody")
            .await
            .expect("test request should write");

        let decoded = Http1ClientStream::new(server)
            .decode_request_head_with_timeout(Duration::from_secs(10))
            .await
            .expect("HTTP/1 request should decode");
        let (_stream, request, head_buffer) = decoded.into_parts();

        assert_eq!(request.method(), Method::GET);
        assert_eq!(request.uri(), "/v1/models");
        assert_eq!(
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok()),
            Some("example.test"),
            "decoded request metadata should expose the Host header"
        );
        assert_eq!(
            head_buffer.head_bytes(),
            b"GET /v1/models HTTP/1.1\r\nHost: example.test\r\n\r\n",
            "decoder must preserve exact request head bytes"
        );
        assert_eq!(
            head_buffer.buffered_body(),
            b"body",
            "decoder must expose body bytes consumed with the request head"
        );
    }

    #[tokio::test]
    async fn decodes_first_response_head_and_preserves_buffered_body() {
        let (mut upstream, stream) = tokio::io::duplex(4096);
        upstream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .expect("test response should write");

        let decoded = Http1UpstreamStream::new(stream)
            .decode_response_head_with_timeout(Duration::from_secs(10))
            .await
            .expect("HTTP/1 response should decode");
        let (_stream, response, head_buffer) = decoded.into_parts();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            head_buffer.head_bytes(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n",
            "decoder must preserve exact response head bytes"
        );
        assert_eq!(
            head_buffer.buffered_body(),
            b"ok",
            "decoder must expose body bytes consumed with the response head"
        );
    }

    #[tokio::test]
    async fn rejects_oversized_request_head() {
        let (mut client, server) = tokio::io::duplex(MAX_HTTP1_HEADER_BYTES * 2);
        let oversized = vec![b'a'; MAX_HTTP1_HEADER_BYTES + 1];
        client
            .write_all(&oversized)
            .await
            .expect("oversized test request should write");

        let error = Http1ClientStream::new(server)
            .decode_request_head_with_timeout(Duration::from_secs(10))
            .await
            .expect_err("oversized request head should be rejected");

        assert!(
            error.to_string().contains("exceeded"),
            "error should explain the size limit"
        );
    }
}
