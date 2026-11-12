//! Configured HTTP upstream origins, independent of Agent protocols and plugins.

use http::{HeaderValue, Request, Uri, header};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::TargetAuthority;

/// Marks a rewritten head so the relay encodes it instead of replaying the original bytes.
#[derive(Clone)]
pub(super) struct Redirected;

/// A redirect destination's HTTP(S) origin. Request paths and queries are retained.
#[derive(Debug, Clone, PartialEq)]
pub struct RedirectTarget {
    origin: Uri,
    authority: TargetAuthority,
}

impl RedirectTarget {
    /// Parses an HTTP(S) origin with an optional port and no path prefix.
    ///
    /// # Errors
    /// Returns a value-free description when the destination is not an origin.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        const INVALID: &str =
            "redirect target must be an HTTP(S) origin with a valid host and port";
        let origin: Uri = value.parse().map_err(|_| INVALID)?;
        let authority = origin.authority().ok_or(INVALID)?;
        let default_port = match origin.scheme_str() {
            Some("http") => 80,
            Some("https") => 443,
            _ => return Err(INVALID),
        };
        if authority.as_str().contains('@')
            || !matches!(origin.path(), "" | "/")
            || origin.query().is_some()
            || value.contains('#')
        {
            return Err(INVALID);
        }
        let authority = if authority.as_str() == authority.host() {
            TargetAuthority::from_host_port(authority.host(), default_port)
        } else {
            TargetAuthority::parse(authority.as_str())
        }
        .map_err(|_| INVALID)?;
        Ok(Self { origin, authority })
    }

    pub(super) const fn authority(&self) -> &TargetAuthority {
        &self.authority
    }

    pub(super) fn server_name(&self) -> Option<String> {
        (self.origin.scheme_str() == Some("https")).then(|| match self.authority.host() {
            crate::TargetHost::Dns(name) => name.clone(),
            crate::TargetHost::Ip(address) => address.to_string(),
        })
    }

    pub(super) fn apply(
        &self,
        request: &mut Request<()>,
    ) -> Result<(), super::TransparentFlowError> {
        let mut parts = request.uri().clone().into_parts();
        parts.scheme = self.origin.scheme().cloned();
        parts.authority = self.origin.authority().cloned();
        let uri = Uri::from_parts(parts).map_err(|source| super::TransparentFlowError::Io {
            operation: super::FlowOperation::LocalRelay,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        })?;
        let host = HeaderValue::from_str(
            self.origin
                .authority()
                .expect("validated redirect origin")
                .as_str(),
        )
        .map_err(|source| super::TransparentFlowError::Io {
            operation: super::FlowOperation::LocalRelay,
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, source),
        })?;
        *request.uri_mut() = uri;
        request.headers_mut().insert(header::HOST, host);
        request.extensions_mut().insert(Redirected);
        Ok(())
    }
}

impl Serialize for RedirectTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&self.origin)
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
    fn rewrites_origin_and_retains_path_query_and_other_headers() {
        let target = RedirectTarget::parse("https://localhost:8443/").unwrap();
        let mut request = Request::builder()
            .uri("/custom/path%2Fpart?q=a%2Bb")
            .header("host", "original.invalid")
            .header("authorization", "Bearer unchanged")
            .body(())
            .unwrap();
        target.apply(&mut request).unwrap();
        assert_eq!(
            request.uri(),
            "https://localhost:8443/custom/path%2Fpart?q=a%2Bb"
        );
        assert_eq!(request.headers()["host"], "localhost:8443");
        assert_eq!(request.headers()["authorization"], "Bearer unchanged");
        assert_eq!(target.server_name().as_deref(), Some("localhost"));
        assert!(request.extensions().get::<Redirected>().is_some());
    }

    #[test]
    fn parses_only_http_origins() {
        for (origin, authority, tls) in [
            ("https://example.com", "example.com:443", true),
            ("http://127.0.0.1:8080", "127.0.0.1:8080", false),
            ("http://[::1]", "[::1]:80", false),
            ("https://[::1]:8443", "[::1]:8443", true),
        ] {
            let target = RedirectTarget::parse(origin).unwrap();
            assert_eq!(target.authority().authority(), authority);
            assert_eq!(target.server_name().is_some(), tls);
            let serialized = serde_json::to_string(&target).unwrap();
            assert_eq!(
                serde_json::from_str::<RedirectTarget>(&serialized).unwrap(),
                target
            );
        }
        for invalid in [
            "example.com",
            "ftp://example.com",
            "https://example.com/v1",
            "https://example.com?x=1",
            "https://example.com#fragment",
            "https://user:pass@example.com",
            "https://localhost:99999",
            "https://localhost:bad",
        ] {
            assert!(RedirectTarget::parse(invalid).is_err(), "{invalid}");
        }
    }
}
