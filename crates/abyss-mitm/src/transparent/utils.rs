//! Small transparent-flow helpers that do not own flow state.
//!
//! The transparent relay modules own sockets, timeout budgets, byte counters,
//! and hook dispatch. Helpers in this module deliberately stay stateless: they
//! classify already-decoded HTTP metadata, serialize small HTTP heads, and parse
//! bounded HTTP body framing. Keeping those rules here makes the relay easier to
//! read without hiding any network side effects.

use http::{
    HeaderMap, Request, StatusCode, Version,
    header::{
        ACCEPT_ENCODING, CONNECTION, CONTENT_LENGTH, EXPECT, HOST, SEC_WEBSOCKET_EXTENSIONS,
        SEC_WEBSOCKET_KEY, TRANSFER_ENCODING, UPGRADE,
    },
};

use crate::http1::Http1Error;

use super::{FlowContext, TransparentProtocol};

pub(super) fn request_host(request: &Request<()>) -> Option<&str> {
    request
        .headers()
        .get(HOST)
        .and_then(|value| value.to_str().ok())
}

/// Returns whether a decoded HTTP/1 request is a WebSocket upgrade request.
///
/// This is intentionally a lightweight classifier for the transparent relay,
/// not a full RFC 6455 server handshake validator. The relay only needs to know
/// when ordinary HTTP body framing stops being valid and the subsequent bytes
/// should be interpreted as WebSocket frames. The downstream server remains the
/// authority that accepts or rejects the handshake.
pub(super) fn is_websocket_upgrade_request(request: &Request<()>) -> bool {
    request.method() == http::Method::GET
        && request.version() == Version::HTTP_11
        && request.headers().contains_key(SEC_WEBSOCKET_KEY)
        && header_contains_token(request.headers(), CONNECTION, "upgrade")
        && header_contains_token(request.headers(), UPGRADE, "websocket")
}

/// Returns whether the relay should strip `Accept-Encoding` for this request.
///
/// Default relay behavior should preserve the client request head byte-for-byte.
/// Claude/Anthropic endpoints are the narrow exception because hooks need
/// parseable plaintext JSON/SSE bodies rather than compressed response payloads.
pub(super) fn should_strip_accept_encoding(flow: &FlowContext, request: &Request<()>) -> bool {
    flow_target_host(flow)
        .or_else(|| request_host(request))
        .is_some_and(is_claude_plaintext_response_host)
}

/// Serializes an HTTP/1 request head after applying relay-owned header rewrites.
///
/// This is used only when transparent relay has to change protocol negotiation
/// headers that affect how the first exchange is streamed. The default path
/// still forwards the original head bytes preserved by the HTTP/1 decoder.
pub(super) fn http_request_head_without_relay_headers(
    request: &Request<()>,
    strip_accept_encoding: bool,
    strip_expect: bool,
) -> Result<Vec<u8>, Http1Error> {
    request_head_bytes_excluding(request, |name| {
        (strip_accept_encoding && name == ACCEPT_ENCODING) || (strip_expect && name == EXPECT)
    })
}

/// Returns whether a request asks the server to send `100 Continue` before body bytes.
pub(super) fn has_expect_continue(request: &Request<()>) -> bool {
    request
        .headers()
        .get_all(EXPECT)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|value| value.trim().eq_ignore_ascii_case("100-continue"))
}

const fn flow_target_host(flow: &FlowContext) -> Option<&str> {
    match &flow.protocol {
        TransparentProtocol::PlainHttp => None,
        TransparentProtocol::TlsHttp { server_name } => Some(server_name.as_str()),
    }
}

fn is_claude_plaintext_response_host(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    host == "anthropic.com"
        || host.ends_with(".anthropic.com")
        || host == "claude.ai"
        || host.ends_with(".claude.ai")
        || host == "dmxapi.cn"
        || host.ends_with(".dmxapi.cn")
}

/// Serializes the request head that should be forwarded for a WebSocket upgrade.
///
/// The relay reuses the structured request decoded by `http1`, then writes a
/// fresh HTTP/1.1 head so it can deliberately remove `Sec-WebSocket-Extensions`.
/// That header is stripped because this first WebSocket relay can decode plain
/// frames but does not yet implement negotiated compression such as
/// `permessage-deflate`.
pub(super) fn websocket_request_head_bytes(request: &Request<()>) -> Result<Vec<u8>, Http1Error> {
    if request.version() != Version::HTTP_11 {
        return Err(Http1Error::UnsupportedBody(
            "WebSocket upgrade requires HTTP/1.1",
        ));
    }

    request_head_bytes_excluding(request, |name| name == SEC_WEBSOCKET_EXTENSIONS)
}

fn request_head_bytes_excluding(
    request: &Request<()>,
    excluded: impl Fn(&http::header::HeaderName) -> bool,
) -> Result<Vec<u8>, Http1Error> {
    let mut head = Vec::new();
    head.extend_from_slice(request.method().as_str().as_bytes());
    head.extend_from_slice(b" ");
    head.extend_from_slice(request_target(request).as_bytes());
    head.extend_from_slice(b" ");
    head.extend_from_slice(request_version_token(request.version())?);
    head.extend_from_slice(b"\r\n");

    for (name, value) in request.headers() {
        if excluded(name) {
            continue;
        }
        head.extend_from_slice(name.as_str().as_bytes());
        head.extend_from_slice(b": ");
        head.extend_from_slice(value.as_bytes());
        head.extend_from_slice(b"\r\n");
    }
    head.extend_from_slice(b"\r\n");
    Ok(head)
}

const fn request_version_token(version: Version) -> Result<&'static [u8], Http1Error> {
    match version {
        Version::HTTP_10 => Ok(b"HTTP/1.0"),
        Version::HTTP_11 => Ok(b"HTTP/1.1"),
        _ => Err(Http1Error::UnsupportedBody(
            "HTTP relay requires an HTTP/1.x request",
        )),
    }
}

/// Returns the HTTP/1 request target that belongs in the serialized request line.
///
/// `http::Uri` may hold an absolute URI for proxy-form requests, but transparent
/// upstreams normally expect origin-form (`/path?query`). Prefer
/// `path_and_query` and fall back to the full URI only when no origin-form target
/// is available.
fn request_target(request: &Request<()>) -> String {
    request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().to_string(), ToString::to_string)
}

/// Returns whether a comma-separated HTTP header contains a token.
///
/// `Connection` and `Upgrade` values are token lists whose matching is
/// case-insensitive. Invalid non-UTF8 header values are ignored because this
/// helper is used only for classification; malformed protocol details will be
/// handled by the upstream server or the stricter WebSocket frame layer.
fn header_contains_token(headers: &HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|value| value.trim().eq_ignore_ascii_case(token))
}

/// Parses a valid `Content-Length` header set.
///
/// RFC-compatible clients can send repeated `Content-Length` fields only when
/// all values are identical. Returning `None` means no length was declared; the
/// caller decides whether that means an empty body or an EOF-delimited response.
pub(super) fn content_length(headers: &HeaderMap) -> Result<Option<usize>, Http1Error> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(first_value) = values.next() else {
        return Ok(None);
    };
    let first_length = parse_content_length_value(first_value)?;
    for value in values {
        if parse_content_length_value(value)? != first_length {
            return Err(Http1Error::InvalidBody(
                "conflicting content-length headers",
            ));
        }
    }
    Ok(Some(first_length))
}

/// Returns whether `Transfer-Encoding` ends in `chunked`.
///
/// HTTP/1 treats transfer codings as an ordered list. `chunked` is the framing
/// marker only when it is the final coding, so `chunked, gzip` is intentionally
/// not accepted here.
pub(super) fn is_chunked(headers: &HeaderMap) -> bool {
    headers
        .get_all(TRANSFER_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .rfind(|item| !item.trim().is_empty())
        .is_some_and(|item| item.trim().eq_ignore_ascii_case("chunked"))
}

fn parse_content_length_value(value: &http::HeaderValue) -> Result<usize, Http1Error> {
    value
        .to_str()
        .map_err(|_error| Http1Error::InvalidBody("invalid content-length"))?
        .parse::<usize>()
        .map_err(|_error| Http1Error::InvalidBody("invalid content-length"))
}

/// Returns whether an HTTP response status cannot carry a message body.
pub(super) fn status_has_no_body(status: StatusCode) -> bool {
    status.is_informational()
        || status == StatusCode::NO_CONTENT
        || status == StatusCode::NOT_MODIFIED
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use http::{
        HeaderMap,
        header::{CONTENT_LENGTH, TRANSFER_ENCODING},
    };

    use super::{
        content_length, has_expect_continue, http_request_head_without_relay_headers, is_chunked,
        is_websocket_upgrade_request, should_strip_accept_encoding, websocket_request_head_bytes,
    };
    use crate::{
        http1::Http1Error,
        transparent::{FlowContext, OriginalDestination, TransparentProtocol},
    };

    #[test]
    fn transfer_encoding_requires_chunked_to_be_final_coding() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, "gzip, chunked".parse().unwrap());

        assert!(is_chunked(&headers));

        headers.insert(TRANSFER_ENCODING, "chunked, gzip".parse().unwrap());

        assert!(
            !is_chunked(&headers),
            "chunked must be the final transfer coding"
        );

        headers.clear();
        headers.append(TRANSFER_ENCODING, "gzip".parse().unwrap());
        headers.append(TRANSFER_ENCODING, "chunked".parse().unwrap());

        assert!(
            is_chunked(&headers),
            "repeated transfer-encoding fields are evaluated in combined order"
        );

        headers.clear();
        headers.append(TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.append(TRANSFER_ENCODING, "gzip".parse().unwrap());

        assert!(
            !is_chunked(&headers),
            "chunked must be final across repeated transfer-encoding fields"
        );
    }

    #[test]
    fn content_length_accepts_duplicate_same_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, "10".parse().unwrap());
        headers.append(CONTENT_LENGTH, "10".parse().unwrap());

        assert_eq!(
            content_length(&headers).expect("matching content-length values should parse"),
            Some(10)
        );
    }

    #[test]
    fn content_length_rejects_conflicting_values() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, "10".parse().unwrap());
        headers.append(CONTENT_LENGTH, "0".parse().unwrap());

        assert!(
            matches!(
                content_length(&headers),
                Err(Http1Error::InvalidBody(
                    "conflicting content-length headers"
                ))
            ),
            "conflicting content-length values must be rejected"
        );
    }

    #[test]
    fn accept_encoding_strip_policy_matches_claude_tls_targets() {
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("host", "api.anthropic.com")
            .header("accept-encoding", "br, gzip, zstd")
            .body(())
            .expect("test HTTP request should build");
        let flow = test_flow(TransparentProtocol::TlsHttp {
            server_name: "api.anthropic.com".to_owned(),
        });

        assert!(
            should_strip_accept_encoding(&flow, &request),
            "Claude/Anthropic targets need uncompressed parseable responses"
        );
    }

    #[test]
    fn accept_encoding_strip_policy_keeps_non_claude_tls_targets() {
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/responses")
            .header("host", "api.openai.com")
            .header("accept-encoding", "br, gzip, zstd")
            .body(())
            .expect("test HTTP request should build");
        let flow = test_flow(TransparentProtocol::TlsHttp {
            server_name: "api.openai.com".to_owned(),
        });

        assert!(
            !should_strip_accept_encoding(&flow, &request),
            "non-Claude targets should preserve the original request head"
        );
    }

    #[test]
    fn http_request_head_rewrite_strips_accept_encoding() {
        let request = http::Request::builder()
            .method("POST")
            .uri("/api/organizations/org-1/chat_conversations/conversation-1/completion")
            .header("host", "claude.ai")
            .header("accept", "text/event-stream")
            .header("accept-encoding", "br, gzip, zstd")
            .header("content-length", "2")
            .body(())
            .expect("test HTTP request should build");

        let head = String::from_utf8(
            http_request_head_without_relay_headers(&request, true, false)
                .expect("head should serialize"),
        )
        .expect("HTTP request head should be UTF-8 in this test");

        assert!(
            head.starts_with(
                "POST /api/organizations/org-1/chat_conversations/conversation-1/completion HTTP/1.1\r\n"
            ),
            "serialized request should preserve request line"
        );
        assert!(
            head.to_ascii_lowercase().contains("host: claude.ai"),
            "serialized request should preserve host"
        );
        assert!(
            head.to_ascii_lowercase().contains("content-length: 2"),
            "serialized request should preserve body framing"
        );
        assert!(
            !head.to_ascii_lowercase().contains("accept-encoding"),
            "Claude request head rewriting strips response content encoding negotiation"
        );
    }

    #[test]
    fn http_request_head_without_relay_headers_strips_selected_headers() {
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/messages?beta=true")
            .header("host", "www.dmxapi.cn")
            .header("accept-encoding", "gzip")
            .header("expect", "100-continue")
            .header("content-length", "4")
            .body(())
            .expect("test HTTP request should build");

        let head = String::from_utf8(
            http_request_head_without_relay_headers(&request, true, true)
                .expect("head should serialize"),
        )
        .expect("HTTP request head should be UTF-8 in this test");
        let lower = head.to_ascii_lowercase();

        assert!(
            head.starts_with("POST /v1/messages?beta=true HTTP/1.1\r\n"),
            "serialized request should preserve request line"
        );
        assert!(
            lower.contains("host: www.dmxapi.cn"),
            "serialized request should preserve destination host"
        );
        assert!(
            lower.contains("content-length: 4"),
            "serialized request should preserve body framing"
        );
        assert!(
            !lower.contains("accept-encoding"),
            "relay rewrite should strip negotiated response compression when requested"
        );
        assert!(
            !lower.contains("expect"),
            "relay rewrite should strip locally-handled 100-continue negotiation"
        );
    }

    #[test]
    fn expect_continue_detection_is_case_insensitive() {
        let request = http::Request::builder()
            .method("POST")
            .uri("/v1/messages")
            .header("expect", "100-CONTINUE")
            .body(())
            .expect("test HTTP request should build");

        assert!(
            has_expect_continue(&request),
            "Expect: 100-continue matching should be case-insensitive"
        );
    }

    #[test]
    fn websocket_upgrade_request_strips_extensions() {
        let request = http::Request::builder()
            .method("GET")
            .uri("/backend-api/codex/responses")
            .header("host", "chatgpt.com")
            .header("connection", "keep-alive, Upgrade")
            .header("upgrade", "websocket")
            .header("sec-websocket-key", "abc")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-extensions", "permessage-deflate")
            .body(())
            .expect("test websocket request should build");

        assert!(
            is_websocket_upgrade_request(&request),
            "upgrade request should be detected before relay"
        );
        let head = String::from_utf8(
            websocket_request_head_bytes(&request)
                .expect("websocket request head should serialize"),
        )
        .expect("websocket request head should be UTF-8 in this test");

        assert!(
            head.starts_with("GET /backend-api/codex/responses HTTP/1.1\r\n"),
            "serialized upgrade request should preserve request line"
        );
        assert!(
            !head
                .to_ascii_lowercase()
                .contains("sec-websocket-extensions"),
            "first WebSocket relay version intentionally disables negotiated compression"
        );
    }

    fn test_flow(protocol: TransparentProtocol) -> FlowContext {
        FlowContext::new(
            SocketAddr::from(([127, 0, 0, 1], 50000)),
            SocketAddr::from(([127, 0, 0, 1], 18080)),
            OriginalDestination::from(SocketAddr::from(([127, 0, 0, 1], 443))),
            protocol,
        )
    }
}
