//! What one exchange's events carry of its request line and headers, as
//! captured.
//!
//! The request path and the header values pass through verbatim. The only
//! change is credential redaction of header values, applied once here with
//! the list owned by `abyss-mitm`. Nothing is read from them.

use abyss_mitm::{REDACTED_HEADER_VALUE, is_sensitive_header};
use abyss_plugin_protocol::event::{HttpHeader, HttpHeaderValue};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderMap, Uri};

/// What one exchange's events carry verbatim: the request path on both
/// events, the request headers on the request event and the response headers
/// on the response event.
#[derive(Debug, Default)]
pub struct ExchangePassthrough {
    /// The request target's path and query, as the request named it.
    pub path: String,
    /// Every request header in capture order, credential values redacted.
    pub request: Vec<HttpHeader>,
    /// Every response header in capture order, credential values redacted.
    pub response: Vec<HttpHeader>,
}

impl ExchangePassthrough {
    /// Copies the captured request target and header maps of one exchange:
    /// the HTTP request and response, or the upgrade request and `101`
    /// response of a WebSocket connection.
    #[must_use]
    pub fn new(target: &Uri, request: &HeaderMap, response: &HeaderMap) -> Self {
        Self {
            path: target
                .path_and_query()
                .map_or_else(|| target.path(), |path| path.as_str())
                .to_owned(),
            request: Self::passthrough(request),
            response: Self::passthrough(response),
        }
    }

    fn passthrough(headers: &HeaderMap) -> Vec<HttpHeader> {
        headers
            .iter()
            .map(|(name, value)| HttpHeader {
                name: name.as_str().to_owned(),
                value: if is_sensitive_header(name) {
                    HttpHeaderValue::Text(REDACTED_HEADER_VALUE.to_owned())
                } else {
                    std::str::from_utf8(value.as_bytes()).map_or_else(
                        |_| HttpHeaderValue::Base64(STANDARD.encode(value.as_bytes())),
                        |value| HttpHeaderValue::Text(value.to_owned()),
                    )
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use abyss_plugin_protocol::event::{HttpHeader, HttpHeaderValue};
    use http::{HeaderMap, HeaderName, HeaderValue, Uri};

    use super::ExchangePassthrough;

    fn headers(entries: &[(&str, &[u8])]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in entries {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_bytes(value).unwrap(),
            );
        }
        headers
    }

    fn text(name: &str, value: &str) -> HttpHeader {
        HttpHeader {
            name: name.to_owned(),
            value: HttpHeaderValue::Text(value.to_owned()),
        }
    }

    #[test]
    fn headers_keep_order_and_duplicates_and_redact_credentials() {
        let captured = ExchangePassthrough::new(
            &Uri::from_static("/v1/messages"),
            &headers(&[
                ("accept", b"application/json"),
                ("authorization", b"Bearer secret"),
                ("accept", b"text/event-stream"),
                ("x-api-key", b"secret"),
                ("anthropic-api-key", b"secret"),
                ("chatgpt-account-id", b"secret"),
                ("x-amz-security-token", b"secret"),
                ("cookie", b"\xffsecret"),
                ("x-binary", b"\xff\xfe"),
                ("x-utf8", "雪山".as_bytes()),
                ("session-id", b" padded {\"json\": 1} "),
            ]),
            &headers(&[
                ("set-cookie", b"a=secret"),
                ("request-id", b"req_1"),
                ("set-cookie", b"b=secret"),
            ]),
        );
        // `HeaderMap` yields every value of a name together, in first-seen
        // name order.
        assert_eq!(
            captured.request,
            [
                text("accept", "application/json"),
                text("accept", "text/event-stream"),
                text("authorization", "<redacted>"),
                text("x-api-key", "<redacted>"),
                text("anthropic-api-key", "<redacted>"),
                text("chatgpt-account-id", "<redacted>"),
                text("x-amz-security-token", "<redacted>"),
                text("cookie", "<redacted>"),
                HttpHeader {
                    name: "x-binary".to_owned(),
                    value: HttpHeaderValue::Base64("//4=".to_owned()),
                },
                text("x-utf8", "雪山"),
                text("session-id", " padded {\"json\": 1} "),
            ]
        );
        assert_eq!(
            captured.response,
            [
                text("set-cookie", "<redacted>"),
                text("set-cookie", "<redacted>"),
                text("request-id", "req_1"),
            ]
        );
    }

    #[test]
    fn path_keeps_the_query_verbatim() {
        let path = |target: &'static str| {
            ExchangePassthrough::new(
                &Uri::from_static(target),
                &HeaderMap::new(),
                &HeaderMap::new(),
            )
            .path
        };
        assert_eq!(path("/v1/messages?beta=true"), "/v1/messages?beta=true");
        assert_eq!(
            path("/v1beta/models/m:generateContent?key=k&alt=sse"),
            "/v1beta/models/m:generateContent?key=k&alt=sse"
        );
        assert_eq!(
            path("/backend-api/codex/responses"),
            "/backend-api/codex/responses"
        );
        // An absolute-form target still yields only its path and query.
        assert_eq!(
            path("https://api.example/v1/responses?x=1"),
            "/v1/responses?x=1"
        );
    }
}
