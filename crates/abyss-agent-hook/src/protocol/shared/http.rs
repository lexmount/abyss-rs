//! HTTP transport metadata; no Harness or protocol identity inference.

use abyss_mitm::{FlowContext, TransparentProtocol};
use http::{HeaderMap, header::HOST};

use super::text::non_empty_trimmed;

pub fn request_host(headers: &HeaderMap, uri: &http::Uri) -> Option<String> {
    uri.host()
        .map(str::to_owned)
        .or_else(|| header(headers, HOST.as_str()).map(str::to_owned))
        .map(|host| normalize_host(&host))
}

fn normalize_host(host: &str) -> String {
    host.split(':')
        .next()
        .unwrap_or(host)
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

pub fn flow_server_name(flow: &FlowContext) -> Option<String> {
    match &flow.protocol {
        TransparentProtocol::TlsHttp { server_name } => Some(normalize_host(server_name)),
        _ => None,
    }
}

pub fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(non_empty_trimmed)
}

/// Reads `OpenCode`'s session headers without treating them as client identity.
pub fn opencode_session_id(headers: &HeaderMap) -> Option<&str> {
    header(headers, "x-opencode-session-id")
        .or_else(|| header(headers, "x-opencode-session"))
        .or_else(|| {
            // The generic alias has session semantics only for this client.
            header(headers, "user-agent")?.strip_prefix("opencode/")?;
            header(headers, "x-session-id")
        })
}

pub const fn transport_name(protocol: &TransparentProtocol) -> &'static str {
    match protocol {
        TransparentProtocol::PlainHttp => "http",
        TransparentProtocol::TlsHttp { .. } => "https",
        _ => "unknown",
    }
}
