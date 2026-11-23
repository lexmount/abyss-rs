//! Session headers carried by provider requests.

use http::HeaderMap;

pub(crate) use crate::http_metadata::{flow_server_name, header, request_host};

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
