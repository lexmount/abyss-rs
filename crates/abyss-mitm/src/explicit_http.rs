//! Explicit HTTP proxy request decoding and normalization.
//!
//! The broker listener owns accepted sockets, target resolution, and proxy
//! responses. This module only consumes the first bounded HTTP/1.1 request head,
//! validates explicit-proxy semantics, and returns the target plus bytes that
//! must be replayed into the shared MITM pipeline. `CONNECT` payload bytes are
//! preserved unchanged, while absolute-form HTTP requests are rewritten to
//! origin form and stripped of proxy-only credentials and headers.

use std::{fmt, io, net::IpAddr, str, time::Duration};

use http::{Uri, uri::Authority};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt as _},
    time,
};

const HEADER_READ_CHUNK_BYTES: usize = 1024;
const MAX_EXPLICIT_PROXY_HEADERS: usize = 64;
const HTTP_HEAD_TERMINATOR: &[u8] = b"\r\n\r\n";

/// Maximum explicit-proxy request-head size accepted by the default decoder.
pub const MAX_EXPLICIT_PROXY_HEADER_BYTES: usize = 16 * 1024;

/// Default whole-operation timeout for reading an explicit-proxy request head.
pub const DEFAULT_EXPLICIT_PROXY_HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// HTTP proxy protocol used to declare the upstream target.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ExplicitProxyProtocol {
    /// HTTPS-style tunnel established with an HTTP `CONNECT` request.
    HttpConnect,
    /// Plain HTTP request carrying an absolute-form request target.
    HttpAbsoluteForm,
}

/// Host portion of an explicit proxy target.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum TargetHost {
    /// Normalized ASCII DNS name without a trailing dot.
    Dns(String),
    /// Canonical IP literal.
    Ip(IpAddr),
}

/// Normalized host and port declared by an explicit proxy request.
#[derive(Debug, Clone, PartialEq)]
pub struct TargetAuthority {
    /// Normalized DNS name or IP literal used for target resolution.
    host: TargetHost,
    /// Nonzero TCP port. `CONNECT` requires this to be explicit, while
    /// absolute-form HTTP may inherit port 80 from the `http` scheme.
    port: u16,
}

/// Explicit request metadata and bytes to replay into the shared MITM pipeline.
pub struct DecodedExplicitRequest {
    /// Authority declared by the proxy client before broker DNS resolution.
    target: TargetAuthority,
    /// Proxy request form that produced the target and replay prefix.
    protocol: ExplicitProxyProtocol,
    /// Bytes that the shared MITM pipeline must see as the start of client IO.
    client_prefix: Box<[u8]>,
}

/// Stable response category for an explicit request decoding failure.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum ExplicitProxyErrorCategory {
    /// The request is malformed or violates explicit-proxy semantics.
    BadRequest,
    /// Reading the complete request head exceeded the whole-operation budget.
    RequestTimeout,
    /// The request head or header count exceeded a configured bound.
    HeaderTooLarge,
    /// The client used an HTTP version unsupported by this explicit proxy.
    VersionNotSupported,
    /// The accepted client connection failed while its request was being read.
    ConnectionIo,
}

/// Errors returned while decoding the first explicit HTTP proxy request.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExplicitRequestError {
    /// The client closed before sending a complete request head.
    #[error("client closed before sending a complete explicit proxy request head")]
    IncompleteRequest,
    /// The request head exceeded the configured byte bound.
    #[error("explicit proxy request head exceeded {limit} bytes")]
    HeaderTooLarge {
        /// Configured request-head byte limit.
        limit: usize,
    },
    /// The parsed request contained more headers than the bounded parser accepts.
    #[error("explicit proxy request contained more than {limit} headers")]
    TooManyHeaders {
        /// Configured maximum number of request headers.
        limit: usize,
    },
    /// The whole request-head read exceeded its timeout budget.
    #[error("explicit proxy request head timed out after {timeout:?}")]
    HeaderTimeout {
        /// Configured whole-operation timeout.
        timeout: Duration,
    },
    /// The request head is not valid HTTP/1 syntax.
    #[error("invalid explicit proxy HTTP/1 request head: {source}")]
    Parse {
        /// Parser failure.
        #[source]
        source: httparse::Error,
    },
    /// Only HTTP/1.1 explicit-proxy requests are accepted.
    #[error("explicit proxy requires HTTP/1.1")]
    UnsupportedVersion,
    /// Required request-line metadata was absent.
    #[error("invalid explicit proxy request: {reason}")]
    InvalidRequest {
        /// Static validation description safe to expose to local callers.
        reason: &'static str,
    },
    /// The request target cannot be used as an upstream authority.
    #[error("invalid explicit proxy target: {reason}")]
    InvalidTarget {
        /// Raw request target or authority.
        target: String,
        /// Static validation description safe to expose to local callers.
        reason: &'static str,
    },
    /// HTTP/1.1 `Host` metadata was missing, duplicated, or invalid.
    #[error("invalid explicit proxy Host header: {reason}")]
    InvalidHost {
        /// Static validation description safe to expose to local callers.
        reason: &'static str,
    },
    /// `Host` and request-target authorities did not identify the same endpoint.
    #[error("explicit proxy Host does not match request target")]
    HostMismatch {
        /// Normalized target authority.
        expected: String,
        /// Client-provided Host value.
        actual: String,
    },
    /// Request body headers create invalid or ambiguous framing.
    #[error("invalid explicit proxy request framing: {reason}")]
    InvalidFraming {
        /// Static validation description safe to expose to local callers.
        reason: &'static str,
    },
    /// Reading the accepted client connection failed.
    #[error("read explicit proxy request head: {source}")]
    Io {
        /// Underlying client connection failure.
        #[source]
        source: io::Error,
    },
}

/// Bounded decoder for the first request on an explicit HTTP proxy connection.
pub struct ExplicitRequestDecoder {
    /// Maximum number of bytes read before the terminating empty line.
    max_header_bytes: usize,
    /// Whole-operation budget for receiving the complete request head.
    header_timeout: Duration,
}

impl TargetHost {
    /// Returns the DNS name when this target was declared by name.
    #[must_use]
    pub fn as_dns_name(&self) -> Option<&str> {
        match self {
            Self::Dns(name) => Some(name),
            Self::Ip(_) => None,
        }
    }

    /// Returns the IP address when this target was declared as a literal.
    #[must_use]
    pub const fn as_ip_addr(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(address) => Some(*address),
            Self::Dns(_) => None,
        }
    }

    fn write_authority_host(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => formatter.write_str(name),
            Self::Ip(IpAddr::V4(address)) => write!(formatter, "{address}"),
            Self::Ip(IpAddr::V6(address)) => write!(formatter, "[{address}]"),
        }
    }
}

impl fmt::Display for TargetHost {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.write_authority_host(formatter)
    }
}

impl TargetAuthority {
    /// Returns the normalized target host.
    #[must_use]
    pub const fn host(&self) -> &TargetHost {
        &self.host
    }

    /// Returns the nonzero target TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns an authority-form representation with an explicit port.
    #[must_use]
    pub fn authority(&self) -> String {
        self.to_string()
    }

    /// Splits the target into its host and port.
    #[must_use]
    pub fn into_parts(self) -> (TargetHost, u16) {
        (self.host, self.port)
    }

    /// Checks whether an HTTP `Host` authority identifies this target.
    ///
    /// `default_port` is selected from the decoded inner protocol: 80 for
    /// plaintext HTTP and 443 for HTTP carried inside a TLS tunnel.
    #[must_use]
    pub fn matches_http_authority(&self, raw: &str, default_port: u16) -> bool {
        parse_target_authority(raw.trim(), Some(default_port))
            .is_ok_and(|declared| declared == *self)
    }

    fn host_header_value(&self, default_port: u16) -> String {
        if self.port == default_port {
            self.host.to_string()
        } else {
            self.to_string()
        }
    }
}

impl fmt::Display for TargetAuthority {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.host.write_authority_host(formatter)?;
        write!(formatter, ":{}", self.port)
    }
}

impl DecodedExplicitRequest {
    /// Returns the normalized target authority.
    #[must_use]
    pub const fn target(&self) -> &TargetAuthority {
        &self.target
    }

    /// Returns the proxy protocol used to declare the target.
    #[must_use]
    pub const fn protocol(&self) -> ExplicitProxyProtocol {
        self.protocol
    }

    /// Returns bytes already read that must be replayed to the MITM pipeline.
    #[must_use]
    pub fn client_prefix(&self) -> &[u8] {
        &self.client_prefix
    }

    /// Splits the decoded request into normalized metadata and replay bytes.
    #[must_use]
    pub fn into_parts(self) -> (TargetAuthority, ExplicitProxyProtocol, Box<[u8]>) {
        (self.target, self.protocol, self.client_prefix)
    }
}

impl ExplicitRequestError {
    /// Returns the stable proxy-response category for this decoder failure.
    #[must_use]
    pub const fn category(&self) -> ExplicitProxyErrorCategory {
        match self {
            Self::HeaderTimeout { .. } => ExplicitProxyErrorCategory::RequestTimeout,
            Self::HeaderTooLarge { .. } | Self::TooManyHeaders { .. } => {
                ExplicitProxyErrorCategory::HeaderTooLarge
            }
            Self::UnsupportedVersion => ExplicitProxyErrorCategory::VersionNotSupported,
            Self::Io { .. } => ExplicitProxyErrorCategory::ConnectionIo,
            Self::IncompleteRequest
            | Self::Parse { .. }
            | Self::InvalidRequest { .. }
            | Self::InvalidTarget { .. }
            | Self::InvalidHost { .. }
            | Self::HostMismatch { .. }
            | Self::InvalidFraming { .. } => ExplicitProxyErrorCategory::BadRequest,
        }
    }
}

impl Default for ExplicitRequestDecoder {
    fn default() -> Self {
        Self::new(DEFAULT_EXPLICIT_PROXY_HEADER_TIMEOUT)
    }
}

impl ExplicitRequestDecoder {
    /// Creates a decoder with the default request-head byte bound.
    #[must_use]
    pub const fn new(header_timeout: Duration) -> Self {
        Self {
            max_header_bytes: MAX_EXPLICIT_PROXY_HEADER_BYTES,
            header_timeout,
        }
    }

    /// Overrides the maximum request-head size for callers and bounded tests.
    #[must_use]
    pub const fn with_max_header_bytes(mut self, max_header_bytes: usize) -> Self {
        self.max_header_bytes = max_header_bytes;
        self
    }

    /// Decodes and normalizes the first explicit proxy request from `stream`.
    ///
    /// The timeout covers the complete request-head operation, preventing a
    /// client from extending the budget by sending one small fragment per read.
    /// The stream remains owned by the caller on both success and failure so the
    /// broker can write the corresponding proxy response.
    ///
    /// # Errors
    ///
    /// Returns an error when the head is incomplete, timed out, too large,
    /// malformed, uses unsupported proxy semantics, or cannot be read.
    pub async fn decode<S>(
        &self,
        stream: &mut S,
    ) -> Result<DecodedExplicitRequest, ExplicitRequestError>
    where
        S: AsyncRead + Unpin,
    {
        let (buffer, head_len) = time::timeout(self.header_timeout, self.read_request_head(stream))
            .await
            .map_err(|_elapsed| ExplicitRequestError::HeaderTimeout {
                timeout: self.header_timeout,
            })??;

        ExplicitRequestParser::new(&buffer, head_len).parse()
    }

    async fn read_request_head<S>(
        &self,
        stream: &mut S,
    ) -> Result<(Vec<u8>, usize), ExplicitRequestError>
    where
        S: AsyncRead + Unpin,
    {
        let mut buffer = Vec::with_capacity(HEADER_READ_CHUNK_BYTES.min(self.max_header_bytes));
        loop {
            // Stop as soon as the HTTP head terminator is present. Any bytes
            // after it are preserved so the MITM pipeline can replay them.
            if let Some(head_len) = find_request_head_len(&buffer) {
                if head_len > self.max_header_bytes {
                    return Err(ExplicitRequestError::HeaderTooLarge {
                        limit: self.max_header_bytes,
                    });
                }
                return Ok((buffer, head_len));
            }
            if buffer.len() >= self.max_header_bytes {
                return Err(ExplicitRequestError::HeaderTooLarge {
                    limit: self.max_header_bytes,
                });
            }

            let remaining = self.max_header_bytes.checked_sub(buffer.len()).ok_or(
                ExplicitRequestError::HeaderTooLarge {
                    limit: self.max_header_bytes,
                },
            )?;
            let mut chunk = [0_u8; HEADER_READ_CHUNK_BYTES];
            let read_len = stream
                .read(&mut chunk[..remaining.min(HEADER_READ_CHUNK_BYTES)])
                .await
                .map_err(|source| ExplicitRequestError::Io { source })?;
            if read_len == 0 {
                return Err(ExplicitRequestError::IncompleteRequest);
            }
            buffer.extend_from_slice(&chunk[..read_len]);
        }
    }
}

/// Parser for a complete explicit-proxy request head plus already-buffered bytes.
///
/// `head_len` isolates the first HTTP request. `buffer[head_len..]` belongs to
/// the tunneled TLS stream or the first plain HTTP request body and must be
/// returned to the caller unchanged unless the proxy request itself is rewritten.
struct ExplicitRequestParser<'a> {
    buffer: &'a [u8],
    head_len: usize,
}

impl<'a> ExplicitRequestParser<'a> {
    const fn new(buffer: &'a [u8], head_len: usize) -> Self {
        Self { buffer, head_len }
    }

    fn parse(self) -> Result<DecodedExplicitRequest, ExplicitRequestError> {
        let mut headers = [httparse::EMPTY_HEADER; MAX_EXPLICIT_PROXY_HEADERS];
        let mut request = httparse::Request::new(&mut headers);
        let parsed_len = match request.parse(&self.buffer[..self.head_len]) {
            Ok(httparse::Status::Complete(parsed_len)) => parsed_len,
            Ok(httparse::Status::Partial) => {
                return Err(ExplicitRequestError::InvalidRequest {
                    reason: "request head remained partial after its terminator",
                });
            }
            Err(httparse::Error::TooManyHeaders) => {
                return Err(ExplicitRequestError::TooManyHeaders {
                    limit: MAX_EXPLICIT_PROXY_HEADERS,
                });
            }
            Err(source) => return Err(ExplicitRequestError::Parse { source }),
        };
        if parsed_len != self.head_len {
            return Err(ExplicitRequestError::InvalidRequest {
                reason: "request parser did not consume the complete head",
            });
        }
        if request.version != Some(1) {
            return Err(ExplicitRequestError::UnsupportedVersion);
        }

        let method = request.method.ok_or(ExplicitRequestError::InvalidRequest {
            reason: "missing method",
        })?;
        let request_target = request.path.ok_or(ExplicitRequestError::InvalidRequest {
            reason: "missing request target",
        })?;

        // `CONNECT` opens a tunnel. Other accepted methods must be plain HTTP
        // explicit-proxy requests with an absolute `http://...` target.
        if method == "CONNECT" {
            self.parse_connect(request_target, request.headers)
        } else {
            self.parse_absolute_http(method, request_target, request.headers)
        }
    }

    fn parse_connect(
        self,
        request_target: &str,
        headers: &[httparse::Header<'_>],
    ) -> Result<DecodedExplicitRequest, ExplicitRequestError> {
        let target = parse_target_authority(request_target, None)?;
        validate_matching_host(headers, &target, target.port)?;
        validate_connect_framing(headers)?;

        // After the broker writes `200 Connection Established`, the preserved
        // prefix becomes the first bytes of the client's tunneled protocol.
        Ok(DecodedExplicitRequest {
            target,
            protocol: ExplicitProxyProtocol::HttpConnect,
            client_prefix: Box::from(&self.buffer[self.head_len..]),
        })
    }

    fn parse_absolute_http(
        self,
        method: &str,
        request_target: &str,
        headers: &[httparse::Header<'_>],
    ) -> Result<DecodedExplicitRequest, ExplicitRequestError> {
        let uri = Uri::try_from(request_target).map_err(|_source| {
            invalid_target(
                request_target,
                "request target must be a valid absolute HTTP URI",
            )
        })?;
        if uri.scheme_str() != Some("http") {
            return Err(invalid_target(
                request_target,
                "plain proxy requests require an http URI",
            ));
        }
        let authority = uri.authority().ok_or_else(|| {
            invalid_target(request_target, "absolute HTTP URI requires an authority")
        })?;
        let target = parse_target_authority(authority.as_str(), Some(80))?;
        validate_matching_host(headers, &target, 80)?;
        validate_http_framing(headers)?;

        // Plain HTTP proxy clients send absolute-form targets to the proxy. The
        // upstream server expects origin-form, so rewrite the request line and
        // strip proxy-only headers before replaying it into the shared pipeline.
        let client_prefix = sanitized_absolute_request_prefix(
            method,
            &uri,
            headers,
            &target,
            &self.buffer[self.head_len..],
        );
        Ok(DecodedExplicitRequest {
            target,
            protocol: ExplicitProxyProtocol::HttpAbsoluteForm,
            client_prefix,
        })
    }
}

/// Returns the byte length of a complete HTTP/1 request head, including CRLFCRLF.
fn find_request_head_len(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(HTTP_HEAD_TERMINATOR.len())
        .position(|window| window == HTTP_HEAD_TERMINATOR)
        .and_then(|offset| offset.checked_add(HTTP_HEAD_TERMINATOR.len()))
}

/// Parses a client-declared authority into the normalized target identity.
///
/// The optional default port is used only where HTTP syntax defines one, such
/// as `http://example.com/path`. `CONNECT` callers pass `None` so the client
/// must declare the exact upstream port.
fn parse_target_authority(
    raw: &str,
    default_port: Option<u16>,
) -> Result<TargetAuthority, ExplicitRequestError> {
    if raw.contains('@') {
        return Err(invalid_target(raw, "userinfo is not allowed"));
    }
    let authority = Authority::try_from(raw)
        .map_err(|_source| invalid_target(raw, "invalid authority syntax"))?;
    let port = match authority.port_u16() {
        Some(port) => port,
        None if authority.port().is_some() => {
            return Err(invalid_target(raw, "port must be a valid u16"));
        }
        None => default_port.ok_or_else(|| invalid_target(raw, "an explicit port is required"))?,
    };
    if port == 0 {
        return Err(invalid_target(raw, "port must not be zero"));
    }
    let host =
        normalize_target_host(authority.host()).map_err(|reason| invalid_target(raw, reason))?;
    Ok(TargetAuthority { host, port })
}

/// Normalizes the host portion without performing DNS resolution.
///
/// Keeping this step purely syntactic ensures the broker records the name the
/// client declared, then resolves that name later at the ingress boundary.
fn normalize_target_host(host: &str) -> Result<TargetHost, &'static str> {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);
    if host.is_empty() {
        return Err("host must not be empty");
    }
    if host.contains('%') {
        return Err("scoped or percent-encoded hosts are not supported");
    }
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(TargetHost::Ip(address));
    }
    if !host.is_ascii() {
        return Err("DNS host must use ASCII or punycode");
    }

    let normalized = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return Err("DNS host length is invalid");
    }
    for label in normalized.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err("DNS label length is invalid");
        }
        let bytes = label.as_bytes();
        if !bytes.first().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
        {
            return Err("DNS labels may contain only letters, digits, and interior hyphens");
        }
    }
    Ok(TargetHost::Dns(normalized))
}

/// Requires HTTP/1.1 `Host` to identify the same target as the request line.
///
/// This prevents a client from declaring one proxy target while sending a
/// conflicting `Host` authority into the shared MITM and audit pipeline.
fn validate_matching_host(
    headers: &[httparse::Header<'_>],
    target: &TargetAuthority,
    host_default_port: u16,
) -> Result<(), ExplicitRequestError> {
    let mut host_headers = headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("host"));
    let host_header = host_headers
        .next()
        .ok_or(ExplicitRequestError::InvalidHost {
            reason: "HTTP/1.1 requires exactly one Host header",
        })?;
    if host_headers.next().is_some() {
        return Err(ExplicitRequestError::InvalidHost {
            reason: "multiple Host headers are not allowed",
        });
    }
    let raw_host = str::from_utf8(host_header.value)
        .map_err(|_source| ExplicitRequestError::InvalidHost {
            reason: "Host must be valid ASCII",
        })?
        .trim();
    if raw_host.is_empty() {
        return Err(ExplicitRequestError::InvalidHost {
            reason: "Host must not be empty",
        });
    }
    let declared = parse_target_authority(raw_host, Some(host_default_port)).map_err(|_error| {
        ExplicitRequestError::InvalidHost {
            reason: "Host must contain a valid authority",
        }
    })?;
    if declared != *target {
        return Err(ExplicitRequestError::HostMismatch {
            expected: target.to_string(),
            actual: raw_host.to_owned(),
        });
    }
    Ok(())
}

/// Validates framing rules for a tunnel request.
///
/// A successful `CONNECT` switches protocols after the response, so a request
/// body on the proxy request itself would be ambiguous and is rejected.
fn validate_connect_framing(headers: &[httparse::Header<'_>]) -> Result<(), ExplicitRequestError> {
    if has_header(headers, "transfer-encoding") {
        return Err(ExplicitRequestError::InvalidFraming {
            reason: "CONNECT must not use Transfer-Encoding",
        });
    }
    if parse_content_length(headers)?.is_some_and(|length| length != 0) {
        return Err(ExplicitRequestError::InvalidFraming {
            reason: "CONNECT must not carry an HTTP request body",
        });
    }
    Ok(())
}

/// Validates plain HTTP proxy request body framing before rewriting the head.
fn validate_http_framing(headers: &[httparse::Header<'_>]) -> Result<(), ExplicitRequestError> {
    let content_length = parse_content_length(headers)?;
    let has_transfer_encoding = has_header(headers, "transfer-encoding");
    if content_length.is_some() && has_transfer_encoding {
        return Err(ExplicitRequestError::InvalidFraming {
            reason: "Content-Length and Transfer-Encoding must not be combined",
        });
    }
    if has_transfer_encoding {
        validate_transfer_encoding(headers)?;
    }
    Ok(())
}

/// Parses duplicate `Content-Length` headers only when they agree exactly.
fn parse_content_length(
    headers: &[httparse::Header<'_>],
) -> Result<Option<usize>, ExplicitRequestError> {
    let mut parsed = None;
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let raw = str::from_utf8(header.value)
            .map_err(|_source| ExplicitRequestError::InvalidFraming {
                reason: "Content-Length must be valid ASCII",
            })?
            .trim();
        let length =
            raw.parse::<usize>()
                .map_err(|_source| ExplicitRequestError::InvalidFraming {
                    reason: "Content-Length must be a nonnegative decimal integer",
                })?;
        if parsed.is_some_and(|previous| previous != length) {
            return Err(ExplicitRequestError::InvalidFraming {
                reason: "conflicting Content-Length headers are not allowed",
            });
        }
        parsed = Some(length);
    }
    Ok(parsed)
}

/// Accepts only HTTP/1.1 transfer coding sequences with final `chunked`.
fn validate_transfer_encoding(
    headers: &[httparse::Header<'_>],
) -> Result<(), ExplicitRequestError> {
    let mut codings = Vec::new();
    for header in headers
        .iter()
        .filter(|header| header.name.eq_ignore_ascii_case("transfer-encoding"))
    {
        let raw = str::from_utf8(header.value).map_err(|_source| {
            ExplicitRequestError::InvalidFraming {
                reason: "Transfer-Encoding must be valid ASCII",
            }
        })?;
        for coding in raw.split(',') {
            let coding = coding.trim();
            if coding.is_empty() {
                return Err(ExplicitRequestError::InvalidFraming {
                    reason: "Transfer-Encoding contains an empty coding",
                });
            }
            codings.push(coding);
        }
    }

    let Some((last, preceding)) = codings.split_last() else {
        return Err(ExplicitRequestError::InvalidFraming {
            reason: "Transfer-Encoding must declare a coding",
        });
    };
    if !last.eq_ignore_ascii_case("chunked") {
        return Err(ExplicitRequestError::InvalidFraming {
            reason: "final Transfer-Encoding coding must be chunked",
        });
    }
    if preceding
        .iter()
        .any(|coding| coding.eq_ignore_ascii_case("chunked"))
    {
        return Err(ExplicitRequestError::InvalidFraming {
            reason: "chunked must appear only as the final Transfer-Encoding coding",
        });
    }
    Ok(())
}

/// Builds the origin-form request bytes replayed for plain HTTP proxy traffic.
///
/// The rewritten prefix is what the upstream server would have received if the
/// client had connected directly instead of speaking explicit-proxy syntax.
fn sanitized_absolute_request_prefix(
    method: &str,
    uri: &Uri,
    headers: &[httparse::Header<'_>],
    target: &TargetAuthority,
    buffered_body: &[u8],
) -> Box<[u8]> {
    let request_target = uri.path_and_query().map_or("/", |value| value.as_str());
    let mut prefix = Vec::new();
    prefix.extend_from_slice(method.as_bytes());
    prefix.extend_from_slice(b" ");
    prefix.extend_from_slice(request_target.as_bytes());
    prefix.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    prefix.extend_from_slice(target.host_header_value(80).as_bytes());
    prefix.extend_from_slice(b"\r\n");
    for header in headers {
        if header.name.eq_ignore_ascii_case("host") || is_proxy_only_header(header.name) {
            continue;
        }
        prefix.extend_from_slice(header.name.as_bytes());
        prefix.extend_from_slice(b": ");
        prefix.extend_from_slice(header.value);
        prefix.extend_from_slice(b"\r\n");
    }
    prefix.extend_from_slice(b"\r\n");
    prefix.extend_from_slice(buffered_body);
    prefix.into_boxed_slice()
}

fn has_header(headers: &[httparse::Header<'_>], expected: &str) -> bool {
    headers
        .iter()
        .any(|header| header.name.eq_ignore_ascii_case(expected))
}

const fn is_proxy_only_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("proxy-authorization")
        || name.eq_ignore_ascii_case("proxy-connection")
        || name.eq_ignore_ascii_case("proxy-authenticate")
}

fn invalid_target(target: &str, reason: &'static str) -> ExplicitRequestError {
    ExplicitRequestError::InvalidTarget {
        target: target.to_owned(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fmt::Write as _,
        net::{IpAddr, Ipv6Addr},
        time::Duration,
    };

    use tokio::io::{AsyncWriteExt as _, duplex};

    use super::{
        ExplicitProxyErrorCategory, ExplicitProxyProtocol, ExplicitRequestDecoder,
        ExplicitRequestError, MAX_EXPLICIT_PROXY_HEADERS, TargetHost,
    };

    #[tokio::test]
    async fn decodes_fragmented_connect_and_preserves_tunnel_prefix() {
        let (mut client, mut server) = duplex(4096);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"CONNECT API.Example.COM:443 HTTP/1.1\r\n")
                .await
                .expect("first fragment should write");
            client
                .write_all(b"Host: api.example.com:443\r\n\r\ntls-prefix")
                .await
                .expect("second fragment should write");
        });

        let decoded = ExplicitRequestDecoder::default()
            .decode(&mut server)
            .await
            .expect("CONNECT should decode");
        writer.await.expect("writer should join");

        assert_eq!(decoded.protocol(), ExplicitProxyProtocol::HttpConnect);
        assert_eq!(decoded.target().authority(), "api.example.com:443");
        assert_eq!(decoded.client_prefix(), b"tls-prefix");
    }

    #[tokio::test]
    async fn decodes_bracketed_ipv6_connect() {
        let decoded =
            decode_once(b"CONNECT [2001:db8::1]:8443 HTTP/1.1\r\nHost: [2001:db8::1]:8443\r\n\r\n")
                .await
                .expect("IPv6 CONNECT should decode");

        assert_eq!(
            decoded.target().host(),
            &TargetHost::Ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,)))
        );
        assert_eq!(decoded.target().authority(), "[2001:db8::1]:8443");
    }

    #[tokio::test]
    async fn rewrites_absolute_http_and_strips_proxy_headers() {
        let decoded = decode_once(
            concat!(
                "POST http://API.Example.COM/v1/messages?beta=true HTTP/1.1\r\n",
                "Host: api.example.com\r\n",
                "Proxy-Authorization: Basic secret\r\n",
                "Proxy-Connection: keep-alive\r\n",
                "Proxy-Authenticate: Basic realm=proxy\r\n",
                "Content-Length: 4\r\n",
                "X-Test: retained\r\n",
                "\r\n",
                "ping"
            )
            .as_bytes(),
        )
        .await
        .expect("absolute-form HTTP should decode");

        assert_eq!(decoded.protocol(), ExplicitProxyProtocol::HttpAbsoluteForm);
        assert_eq!(decoded.target().authority(), "api.example.com:80");
        let prefix = str::from_utf8(decoded.client_prefix()).expect("prefix should be UTF-8");
        assert!(
            prefix.starts_with("POST /v1/messages?beta=true HTTP/1.1\r\nHost: api.example.com\r\n")
        );
        assert!(prefix.contains("Content-Length: 4\r\n"));
        assert!(prefix.contains("X-Test: retained\r\n"));
        assert!(!prefix.to_ascii_lowercase().contains("proxy-"));
        assert!(prefix.ends_with("\r\nping"));
    }

    #[tokio::test]
    async fn rejects_host_mismatch() {
        let error = decode_once(
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: other.example.com:443\r\n\r\n",
        )
        .await
        .err()
        .expect("mismatched Host should fail");

        assert!(matches!(error, ExplicitRequestError::HostMismatch { .. }));
        assert_eq!(error.category(), ExplicitProxyErrorCategory::BadRequest);
    }

    #[tokio::test]
    async fn rejects_duplicate_host() {
        let error = decode_once(
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nHost: api.example.com:443\r\n\r\n",
        )
        .await
        .err()
        .expect("duplicate Host should fail");

        assert!(matches!(error, ExplicitRequestError::InvalidHost { .. }));
    }

    #[tokio::test]
    async fn rejects_connect_body_framing() {
        let error = decode_once(
            b"CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\nContent-Length: 1\r\n\r\nx",
        )
        .await
        .err()
        .expect("CONNECT body should fail");

        assert!(matches!(error, ExplicitRequestError::InvalidFraming { .. }));
    }

    #[tokio::test]
    async fn rejects_connect_without_an_explicit_nonzero_port() {
        for request in [
            &b"CONNECT api.example.com HTTP/1.1\r\nHost: api.example.com\r\n\r\n"[..],
            &b"CONNECT api.example.com:0 HTTP/1.1\r\nHost: api.example.com:0\r\n\r\n"[..],
            &b"CONNECT api.example.com:99999 HTTP/1.1\r\nHost: api.example.com:99999\r\n\r\n"[..],
        ] {
            let error = decode_once(request)
                .await
                .err()
                .expect("invalid CONNECT port should fail");

            assert!(matches!(error, ExplicitRequestError::InvalidTarget { .. }));
        }
    }

    #[tokio::test]
    async fn rejects_missing_host_header() {
        let error = decode_once(b"CONNECT api.example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .err()
            .expect("missing Host should fail");

        assert!(matches!(error, ExplicitRequestError::InvalidHost { .. }));
    }

    #[tokio::test]
    async fn rejects_unsupported_or_non_absolute_http_targets_without_logging_them() {
        for request in [
            &b"GET https://api.example.com/private?token=secret HTTP/1.1\r\nHost: api.example.com\r\n\r\n"[..],
            &b"GET /origin-form HTTP/1.1\r\nHost: api.example.com\r\n\r\n"[..],
            &b"OPTIONS * HTTP/1.1\r\nHost: api.example.com\r\n\r\n"[..],
            &b"GET http://user:secret@api.example.com/ HTTP/1.1\r\nHost: api.example.com\r\n\r\n"[..],
        ] {
            let error = decode_once(request)
                .await
                .err()
                .expect("unsupported target should fail");
            let display = error.to_string();

            assert!(matches!(
                error,
                ExplicitRequestError::InvalidTarget { .. }
            ));
            assert!(!display.contains("secret"));
            assert!(!display.contains("private"));
        }
    }

    #[tokio::test]
    async fn rejects_ambiguous_absolute_http_framing() {
        let error = decode_once(
            concat!(
                "POST http://api.example.com/ HTTP/1.1\r\n",
                "Host: api.example.com\r\n",
                "Content-Length: 4\r\n",
                "Transfer-Encoding: chunked\r\n",
                "\r\n"
            )
            .as_bytes(),
        )
        .await
        .err()
        .expect("ambiguous framing should fail");

        assert!(matches!(error, ExplicitRequestError::InvalidFraming { .. }));
    }

    #[tokio::test]
    async fn rejects_conflicting_content_lengths_and_invalid_transfer_encoding() {
        for request in [
            concat!(
                "POST http://api.example.com/ HTTP/1.1\r\n",
                "Host: api.example.com\r\n",
                "Content-Length: 3\r\n",
                "Content-Length: 4\r\n",
                "\r\n"
            ),
            concat!(
                "POST http://api.example.com/ HTTP/1.1\r\n",
                "Host: api.example.com\r\n",
                "Transfer-Encoding: chunked, gzip\r\n",
                "\r\n"
            ),
        ] {
            let error = decode_once(request.as_bytes())
                .await
                .err()
                .expect("ambiguous request framing should fail");

            assert!(matches!(error, ExplicitRequestError::InvalidFraming { .. }));
        }
    }

    #[tokio::test]
    async fn rejects_http_10_with_version_category() {
        let error = decode_once(
            b"CONNECT api.example.com:443 HTTP/1.0\r\nHost: api.example.com:443\r\n\r\n",
        )
        .await
        .err()
        .expect("HTTP/1.0 should fail");

        assert!(matches!(error, ExplicitRequestError::UnsupportedVersion));
        assert_eq!(
            error.category(),
            ExplicitProxyErrorCategory::VersionNotSupported
        );
    }

    #[tokio::test]
    async fn reports_incomplete_closed_request_as_bad_request() {
        let error = decode_once(b"CONNECT api.example.com:443 HTTP/1.1\r\nHost:")
            .await
            .err()
            .expect("closed partial request should fail");

        assert!(matches!(error, ExplicitRequestError::IncompleteRequest));
        assert_eq!(error.category(), ExplicitProxyErrorCategory::BadRequest);
    }

    #[tokio::test]
    async fn reports_excessive_header_count_as_header_too_large() {
        let mut request =
            String::from("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n");
        for index in 0..MAX_EXPLICIT_PROXY_HEADERS {
            write!(request, "X-Test-{index}: value\r\n")
                .expect("writing a test header to String should succeed");
        }
        request.push_str("\r\n");

        let error = decode_once(request.as_bytes())
            .await
            .err()
            .expect("excessive header count should fail");

        assert!(matches!(error, ExplicitRequestError::TooManyHeaders { .. }));
        assert_eq!(error.category(), ExplicitProxyErrorCategory::HeaderTooLarge);
    }

    #[tokio::test]
    async fn enforces_whole_operation_timeout() {
        let (mut client, mut server) = duplex(64);
        let writer = tokio::spawn(async move {
            client
                .write_all(b"CONNECT ")
                .await
                .expect("partial request should write");
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let error = ExplicitRequestDecoder::new(Duration::from_millis(20))
            .decode(&mut server)
            .await
            .err()
            .expect("slow request should time out");
        writer.abort();

        assert!(matches!(error, ExplicitRequestError::HeaderTimeout { .. }));
        assert_eq!(error.category(), ExplicitProxyErrorCategory::RequestTimeout);
    }

    #[tokio::test]
    async fn accepts_head_exactly_at_configured_limit() {
        let request = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
        let (mut client, mut server) = duplex(256);
        client
            .write_all(request)
            .await
            .expect("request should write");
        let decoded = ExplicitRequestDecoder::default()
            .with_max_header_bytes(request.len())
            .decode(&mut server)
            .await
            .expect("head at exact limit should decode");

        assert_eq!(decoded.target().authority(), "a.test:443");
    }

    #[tokio::test]
    async fn rejects_complete_head_over_configured_limit() {
        let request = b"CONNECT a.test:443 HTTP/1.1\r\nHost: a.test:443\r\n\r\n";
        let (mut client, mut server) = duplex(256);
        client
            .write_all(request)
            .await
            .expect("request should write");
        let error = ExplicitRequestDecoder::default()
            .with_max_header_bytes(request.len() - 1)
            .decode(&mut server)
            .await
            .err()
            .expect("head over limit should fail");

        assert!(matches!(error, ExplicitRequestError::HeaderTooLarge { .. }));
        assert_eq!(error.category(), ExplicitProxyErrorCategory::HeaderTooLarge);
    }

    async fn decode_once(
        request: &[u8],
    ) -> Result<super::DecodedExplicitRequest, ExplicitRequestError> {
        let capacity = request
            .len()
            .checked_add(16)
            .expect("test capacity should fit");
        let (mut client, mut server) = duplex(capacity);
        client
            .write_all(request)
            .await
            .expect("request should write");
        drop(client);
        ExplicitRequestDecoder::default().decode(&mut server).await
    }
}
