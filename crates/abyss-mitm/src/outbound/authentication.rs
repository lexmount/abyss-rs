//! Basic authentication for the configured next hop; never inherits Agent credentials.

use std::{path::Path, sync::Arc};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;

use super::{UpstreamProxyConfigError, config::read_material};

/// Secret header value retained by a route snapshot, deliberately without Debug/Serialize.
#[derive(Clone)]
pub(super) struct ProxyAuthorization(Arc<str>);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BasicCredentials {
    username: String,
    password: String,
}

impl ProxyAuthorization {
    pub(super) fn load(path: &Path) -> Result<Self, UpstreamProxyConfigError> {
        let bytes = read_material(path, 16 * 1024)?;
        let credentials: BasicCredentials = serde_json::from_slice(&bytes).map_err(|_| {
            UpstreamProxyConfigError("proxy credentials must be a JSON username/password object")
        })?;
        if credentials.username.contains(':')
            || credentials
                .username
                .chars()
                .chain(credentials.password.chars())
                .any(char::is_control)
        {
            return Err(UpstreamProxyConfigError(
                "proxy username must not contain ':' and credentials must not contain control characters",
            ));
        }
        let encoded = STANDARD.encode(format!("{}:{}", credentials.username, credentials.password));
        Ok(Self(Arc::from(format!("Basic {encoded}"))))
    }

    pub(super) fn append_to(&self, request: &mut String) {
        request.push_str("Proxy-Authorization: ");
        request.push_str(&self.0);
        request.push_str("\r\n");
    }
}
