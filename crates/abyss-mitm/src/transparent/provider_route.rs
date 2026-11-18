//! Transport selection for an inspected model call, including its HTTPS authority and API path.

use http::{HeaderName, HeaderValue, Request, Uri, header};

use super::RequestEditor;
use crate::TargetAuthority;

/// Destination owned by the inspected HTTP request or WebSocket upgrade.
#[derive(Clone)]
pub struct ProviderRoute {
    target: TargetAuthority,
    tls_name: String,
    uri: Uri,
}

impl ProviderRoute {
    /// Parse the complete HTTPS endpoint supplied by the configured provider.
    ///
    /// # Errors
    /// Returns an error for an invalid HTTPS authority or target.
    pub fn parse(url: &str) -> Result<Self, &'static str> {
        let uri: Uri = url.parse().map_err(|_| "invalid provider URI")?;
        let authority = uri.authority().ok_or("missing provider authority")?;
        if uri.scheme_str() != Some("https") || authority.as_str().contains('@') {
            return Err("invalid provider HTTPS authority");
        }
        let tls_name = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let target =
            TargetAuthority::from_host_port(&tls_name, authority.port_u16().unwrap_or(443))
                .map_err(|_| "invalid provider target")?;
        Ok(Self {
            target,
            tls_name,
            uri,
        })
    }

    pub(super) const fn target(&self) -> &TargetAuthority {
        &self.target
    }

    pub(super) fn tls_name(&self) -> &str {
        &self.tls_name
    }

    /// Build the new origin's request head from wire protocol fields and the configured credentials.
    /// The caller installs explicit credential fields after selecting the route.
    pub(super) fn apply(&self, head: &mut Request<()>) -> Result<(), &'static str> {
        let mut headers = http::HeaderMap::new();
        for (name, value) in head.headers() {
            if protocol_header(name) {
                headers.append(name.clone(), value.clone());
            }
        }
        let authority = self.uri.authority().ok_or("missing provider authority")?;
        headers.insert(
            header::HOST,
            HeaderValue::from_str(authority.as_str()).map_err(|_| "invalid provider authority")?,
        );
        *head.headers_mut() = headers;
        *head.uri_mut() = self.uri.clone();
        head.extensions_mut().insert(self.clone());
        Ok(())
    }
}

fn protocol_header(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "accept"
            | "accept-encoding"
            | "content-type"
            | "content-length"
            | "content-encoding"
            | "transfer-encoding"
            | "expect"
            | "user-agent"
            | "upgrade"
            | "connection"
            | "sec-websocket-key"
            | "sec-websocket-version"
            | "anthropic-version"
            | "anthropic-beta"
            | "openai-beta"
    )
}

impl RequestEditor<'_> {
    /// Select the HTTPS destination for this HTTP exchange.
    ///
    /// # Errors
    /// Invalid providers and attempts to reroute established connections return an error.
    pub fn route_provider(&mut self, endpoint: &str) -> Result<(), &'static str> {
        if !matches!(self.view().transport, super::RequestTransport::Http) {
            return Err("provider route requires an HTTP request");
        }
        let decoded = self.view().body.bytes_ref().clone();
        ProviderRoute::parse(endpoint)?.apply(self.edited_head())?;
        // Reframe decoded content for the new origin, including requests with original trailers.
        self.replace_body(decoded);
        Ok(())
    }
}
