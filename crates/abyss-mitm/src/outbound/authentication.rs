//! Basic authentication for the configured next hop; never inherits Agent credentials.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};

use super::config::ProxyCredentials;

/// Secret header value retained by a route snapshot, deliberately without Debug/Serialize.
#[derive(Clone)]
pub(super) struct ProxyAuthorization(Arc<str>);

impl ProxyAuthorization {
    pub(super) fn new(credentials: &ProxyCredentials) -> Self {
        let encoded = STANDARD.encode(format!("{}:{}", credentials.username, credentials.password));
        Self(Arc::from(format!("Basic {encoded}")))
    }

    pub(super) fn append_to(&self, request: &mut String) {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&self.0);
        request.push_str("\r\n");
    }
}
