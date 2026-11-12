//! Configured domain replacements, independent of Agent protocols and plugins.

use http::{HeaderValue, Request, Uri, header, uri::Authority};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Marks a rewritten head so the relay encodes it instead of replaying the original bytes.
#[derive(Clone)]
pub(super) struct Redirected;

/// A replacement domain. The original protocol, port, path and query are retained.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectTarget {
    host: String,
}

impl RedirectTarget {
    /// Parses a domain name without a scheme, port or path.
    ///
    /// # Errors
    /// Returns an error for anything other than a DNS name.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        match crate::explicit_http::normalize_target_host(value) {
            Ok(crate::TargetHost::Dns(host)) => Ok(Self { host }),
            _ => Err("redirect target must be a domain name without a scheme, port or path"),
        }
    }

    pub(super) fn host(&self) -> &str {
        &self.host
    }

    pub(super) fn apply(
        &self,
        request: &mut Request<()>,
    ) -> Result<(), super::TransparentFlowError> {
        // Absolute-form URIs retain their scheme and explicit port. Origin-form
        // URIs need no changes: their hostname lives in the Host header.
        if let Some(authority) = request.uri().authority() {
            let authority = self.with_port(authority.port_u16());
            let mut parts = request.uri().clone().into_parts();
            parts.authority = Some(authority.parse().map_err(Self::invalid_head)?);
            *request.uri_mut() = Uri::from_parts(parts).map_err(Self::invalid_head)?;
        }
        let authority = request
            .headers()
            .get(header::HOST)
            .map(|value| {
                value
                    .to_str()
                    .map_err(Self::invalid_head)?
                    .parse::<Authority>()
                    .map_err(Self::invalid_head)
            })
            .transpose()?;
        let host = self.with_port(authority.as_ref().and_then(Authority::port_u16));
        request.headers_mut().insert(
            header::HOST,
            HeaderValue::from_str(&host).map_err(Self::invalid_head)?,
        );
        request.extensions_mut().insert(Redirected);
        Ok(())
    }

    fn with_port(&self, port: Option<u16>) -> String {
        port.map_or_else(|| self.host.clone(), |port| format!("{}:{port}", self.host))
    }

    fn invalid_head(
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> super::TransparentFlowError {
        super::TransparentFlowError::Io {
            operation: super::FlowOperation::LocalRelay,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        }
    }
}

impl Serialize for RedirectTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.host)
    }
}

impl<'de> Deserialize<'de> for RedirectTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_the_domain_in_origin_and_absolute_forms() {
        let target = RedirectTarget::parse("replacement.example").unwrap();
        for (uri, host, expected_uri, expected_host) in [
            (
                "/custom/path%2Fpart?q=a%2Bb",
                "original.invalid",
                "/custom/path%2Fpart?q=a%2Bb",
                "replacement.example",
            ),
            (
                "/custom/path%2Fpart?q=a%2Bb",
                "original.invalid:8443",
                "/custom/path%2Fpart?q=a%2Bb",
                "replacement.example:8443",
            ),
            (
                "https://original.invalid:8443/path?q=1",
                "original.invalid:8443",
                "https://replacement.example:8443/path?q=1",
                "replacement.example:8443",
            ),
            (
                "http://original.invalid:8080/path?q=1",
                "original.invalid:8080",
                "http://replacement.example:8080/path?q=1",
                "replacement.example:8080",
            ),
            (
                "https://original.invalid:443/path",
                "original.invalid:443",
                "https://replacement.example:443/path",
                "replacement.example:443",
            ),
        ] {
            let mut request = Request::builder()
                .uri(uri)
                .header("host", host)
                .header("authorization", "Bearer unchanged")
                .body(())
                .unwrap();
            target.apply(&mut request).unwrap();
            assert_eq!(request.uri(), expected_uri);
            assert_eq!(request.headers()["host"], expected_host);
            assert_eq!(request.headers()["authorization"], "Bearer unchanged");
            assert!(request.extensions().get::<Redirected>().is_some());
        }
    }

    #[test]
    fn accepts_only_domain_names() {
        for name in ["api.deepseek.com", "localhost", "xn--bcher-kva.example"] {
            let target = RedirectTarget::parse(name).unwrap();
            assert_eq!(target.host(), name);
            let serialized = serde_json::to_string(&target).unwrap();
            assert_eq!(serialized, format!("\"{name}\""));
            assert_eq!(
                serde_json::from_str::<RedirectTarget>(&serialized).unwrap(),
                target
            );
        }
        for invalid in [
            "",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "example.com?x=1",
            "example.com#fragment",
            "user@example.com",
            "*.example.com",
            "127.0.0.1",
            "[::1]",
        ] {
            assert!(RedirectTarget::parse(invalid).is_err(), "{invalid}");
        }
    }
}
