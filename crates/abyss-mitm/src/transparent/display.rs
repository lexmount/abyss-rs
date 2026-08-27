//! Display adapters for captured transparent HTTP data.
//!
//! The MITM crate owns the shape and semantics of captured HTTP exchanges, so
//! it also owns their human-readable rendering. Concrete hook crates can then
//! log or export these adapters without duplicating formatting rules.

use std::fmt;

use http::{HeaderMap, HeaderValue, Request, Response, header::HeaderName};

use super::{CapturedBody, FlowContext, HttpExchange};

/// Display adapter for a decoded request head.
pub struct HttpRequestHeadDisplay<'a> {
    request: &'a Request<CapturedBody>,
}

impl<'a> HttpRequestHeadDisplay<'a> {
    /// Creates a request-head display adapter.
    #[must_use]
    pub const fn new(request: &'a Request<CapturedBody>) -> Self {
        Self { request }
    }
}

impl fmt::Display for HttpRequestHeadDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} {:?}\n{}",
            self.request.method(),
            self.request.uri().path(),
            self.request.version(),
            HttpHeadersDisplay::new(self.request.headers())
        )
    }
}

/// Display adapter for a decoded response head.
pub struct HttpResponseHeadDisplay<'a> {
    response: &'a Response<CapturedBody>,
}

impl<'a> HttpResponseHeadDisplay<'a> {
    /// Creates a response-head display adapter.
    #[must_use]
    pub const fn new(response: &'a Response<CapturedBody>) -> Self {
        Self { response }
    }
}

impl fmt::Display for HttpResponseHeadDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{:?} {}\n{}",
            self.response.version(),
            self.response.status(),
            HttpHeadersDisplay::new(self.response.headers())
        )
    }
}

/// Display adapter for HTTP headers.
pub struct HttpHeadersDisplay<'a> {
    headers: &'a HeaderMap,
}

impl<'a> HttpHeadersDisplay<'a> {
    /// Creates a header display adapter.
    #[must_use]
    pub const fn new(headers: &'a HeaderMap) -> Self {
        Self { headers }
    }
}

impl fmt::Display for HttpHeadersDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.headers.is_empty() {
            return formatter.write_str("<empty>");
        }

        let mut separator = "";
        for (name, value) in self.headers {
            write!(formatter, "{separator}{}: ", name.as_str())?;
            if is_sensitive_header(name) {
                formatter.write_str("<redacted>")?;
            } else {
                HeaderValueDisplay::new(value).fmt(formatter)?;
            }
            separator = "\n";
        }
        Ok(())
    }
}

fn is_sensitive_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    matches!(
        name,
        "authorization"
            | "proxy-authorization"
            | "cookie"
            | "set-cookie"
            | "api-key"
            | "x-api-key"
            | "x-goog-api-key"
    ) || name.contains("token")
}

struct HeaderValueDisplay<'a> {
    value: &'a HeaderValue,
}

impl<'a> HeaderValueDisplay<'a> {
    const fn new(value: &'a HeaderValue) -> Self {
        Self { value }
    }
}

impl fmt::Display for HeaderValueDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.value.to_str() {
            Ok(value) => formatter.write_str(value),
            Err(_error) => write!(
                formatter,
                "<non-utf8: {} bytes>",
                self.value.as_bytes().len()
            ),
        }
    }
}

/// Explicit plaintext display adapter for a captured body.
///
/// Body rendering can include credentials, prompts, responses, or other
/// sensitive payloads. Callers must opt into this adapter instead of relying on
/// an implicit `Display` implementation for [`CapturedBody`].
pub struct CapturedBodyPlaintextDisplay<'a> {
    body: &'a CapturedBody,
}

impl<'a> CapturedBodyPlaintextDisplay<'a> {
    /// Creates a plaintext body display adapter.
    #[must_use]
    pub const fn new(body: &'a CapturedBody) -> Self {
        Self { body }
    }
}

impl fmt::Display for CapturedBodyPlaintextDisplay<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "bytes={}", self.body.bytes().len())?;

        if let Some(json) = self.body.json() {
            write!(formatter, "\njson={json}")?;
        }

        write!(
            formatter,
            "\ntext={}",
            String::from_utf8_lossy(self.body.bytes())
        )
    }
}

impl fmt::Display for FlowContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "flow_id={} peer_addr={:?} local_addr={:?} original_destination={} destination_host={:?} protocol={:?} ingress={:?}",
            self.flow_id,
            self.peer_addr,
            self.local_addr,
            self.original_destination,
            self.destination_host,
            self.protocol,
            self.ingress
        )
    }
}

impl CapturedBody {
    /// Returns an explicit plaintext display adapter for this body.
    #[must_use]
    pub const fn display_plaintext(&self) -> CapturedBodyPlaintextDisplay<'_> {
        CapturedBodyPlaintextDisplay::new(self)
    }
}

impl HttpExchange {
    /// Returns a display adapter for the captured request head.
    #[must_use]
    pub const fn request_head_display(&self) -> HttpRequestHeadDisplay<'_> {
        HttpRequestHeadDisplay::new(&self.request)
    }

    /// Returns a display adapter for the captured response head.
    #[must_use]
    pub const fn response_head_display(&self) -> HttpResponseHeadDisplay<'_> {
        HttpResponseHeadDisplay::new(&self.response)
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use bytes::Bytes;
    use http::{HeaderMap, HeaderValue, Request, Response, header};

    use super::{
        CapturedBodyPlaintextDisplay, HttpHeadersDisplay, HttpRequestHeadDisplay,
        HttpResponseHeadDisplay,
    };
    use crate::transparent::{CapturedBody, FlowContext, OriginalDestination, TransparentProtocol};

    #[test]
    fn flow_context_display_includes_platform_flow_metadata() {
        let context = FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18090)),
            OriginalDestination::from(SocketAddr::from(([10, 0, 0, 1], 443))),
            TransparentProtocol::TlsHttp {
                server_name: "api.example.test".to_owned(),
            },
        );

        let rendered = context.to_string();

        assert!(
            rendered.contains("peer_addr=Some(127.0.0.1:50000)"),
            "peer address should be logged"
        );
        assert!(
            rendered.contains("original_destination=10.0.0.1:443"),
            "original destination should be logged"
        );
        assert!(
            rendered.contains("api.example.test"),
            "TLS server name should be logged"
        );
    }

    #[test]
    fn header_display_keeps_safe_values_and_redacts_credentials() {
        let mut headers = HeaderMap::new();
        headers.append(header::ACCEPT, HeaderValue::from_static("application/json"));
        headers.append(
            header::ACCEPT,
            HeaderValue::from_static("text/event-stream"),
        );
        headers.append(
            "x-binary",
            HeaderValue::from_bytes(b"\xff\xfe").expect("test header bytes should build"),
        );
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer query-secret"),
        );
        headers.append(
            header::COOKIE,
            HeaderValue::from_static("session=query-secret"),
        );

        let rendered = HttpHeadersDisplay::new(&headers).to_string();

        assert!(
            rendered.contains("accept: application/json"),
            "first repeated header should be logged"
        );
        assert!(
            rendered.contains("accept: text/event-stream"),
            "second repeated header should be logged"
        );
        assert!(
            rendered.contains("x-binary: <non-utf8: 2 bytes>"),
            "non-UTF-8 headers should not panic or lose size context"
        );
        assert!(rendered.contains("authorization: <redacted>"));
        assert!(rendered.contains("cookie: <redacted>"));
        assert!(!rendered.contains("query-secret"));
    }

    #[test]
    fn body_plaintext_display_includes_byte_count_text_and_json_view() {
        let body = CapturedBody::from_bytes(Bytes::from_static(br#"{"ok":true}"#));

        let rendered = CapturedBodyPlaintextDisplay::new(&body).to_string();

        assert!(
            rendered.contains("bytes=11"),
            "body byte count should be logged"
        );
        assert!(
            rendered.contains(r#"json={"ok":true}"#),
            "JSON body enrichment should be logged"
        );
        assert!(
            rendered.contains(r#"text={"ok":true}"#),
            "raw body text should be logged"
        );
    }

    #[test]
    fn request_and_response_head_display_include_http_metadata() {
        let request = Request::builder()
            .method("POST")
            .uri("/v1/chat/completions?api_key=query-secret")
            .header(header::HOST, "api.example.test")
            .body(CapturedBody::from_bytes(Bytes::new()))
            .expect("test request should build");
        let response = Response::builder()
            .status(429)
            .header(header::CONTENT_TYPE, "application/json")
            .body(CapturedBody::from_bytes(Bytes::new()))
            .expect("test response should build");

        assert!(
            HttpRequestHeadDisplay::new(&request)
                .to_string()
                .contains("POST /v1/chat/completions"),
            "request line should be logged"
        );
        assert!(
            !HttpRequestHeadDisplay::new(&request)
                .to_string()
                .contains("query-secret"),
            "request display must not expose query credentials"
        );
        assert!(
            HttpRequestHeadDisplay::new(&request)
                .to_string()
                .contains("host: api.example.test"),
            "request headers should be logged"
        );
        assert!(
            HttpResponseHeadDisplay::new(&response)
                .to_string()
                .contains("429 Too Many Requests"),
            "response status should be logged"
        );
        assert!(
            HttpResponseHeadDisplay::new(&response)
                .to_string()
                .contains("content-type: application/json"),
            "response headers should be logged"
        );
    }
}
