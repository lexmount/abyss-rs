//! API-root normalization that preserves reverse-proxy path prefixes.

use reqwest::Url;

use crate::DataClientError;

/// Validated HTTP API root, including an optional prefix such as `/api/`.
#[derive(Clone)]
pub struct ApiEndpoint(Url);

impl ApiEndpoint {
    /// Validates a root without URL credentials, query strings or fragments.
    /// Remote connections require HTTPS; HTTP is permitted on loopback only.
    ///
    /// # Errors
    /// Returns an error for an unsafe or malformed URL.
    pub fn parse(value: &str) -> Result<Self, DataClientError> {
        Self::parse_with_http(value, false)
    }

    /// Validates an API root, optionally allowing unencrypted remote HTTP.
    /// This opt-in also permits sending bearer credentials over that connection.
    ///
    /// # Errors
    /// Returns an error for malformed URLs or embedded credentials.
    pub fn parse_with_http(value: &str, allow_http: bool) -> Result<Self, DataClientError> {
        let mut url = Url::parse(value.trim()).map_err(|_| {
            DataClientError::Configuration("API root must be an absolute HTTP(S) URL")
        })?;
        let loopback = url.host_str().is_some_and(|host| {
            host.eq_ignore_ascii_case("localhost")
                || host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|address| address.is_loopback())
        });
        if url.host_str().is_none()
            || !(url.scheme() == "https" || (url.scheme() == "http" && (loopback || allow_http)))
        {
            return Err(DataClientError::Configuration(
                "use HTTPS, or HTTP on loopback",
            ));
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(DataClientError::Configuration(
                "API root must not contain credentials, a query or a fragment",
            ));
        }
        let path = format!("{}/", url.path().trim_end_matches('/'));
        url.set_path(&path);
        Ok(Self(url))
    }

    /// Returns the normalized API root.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Appends encoded path segments without dropping the API prefix.
    pub(crate) fn resource(&self, segments: &[&str]) -> Url {
        let mut url = self.0.clone();
        url.path_segments_mut()
            .expect("validated HTTP URL supports path segments")
            .pop_if_empty()
            .extend(segments.iter().copied());
        url
    }
}

#[cfg(test)]
mod tests {
    use super::ApiEndpoint;

    #[test]
    fn normalizes_prefix_and_encodes_only_new_segments() {
        let root = ApiEndpoint::parse("https://example.test/a%20b/api").expect("valid prefix");
        assert_eq!(
            root.as_str(),
            "https://example.test/a%20b/api/",
            "preserve percent-encoded prefix"
        );
        assert_eq!(
            root.resource(&["events", "x/y"]).as_str(),
            "https://example.test/a%20b/api/events/x%2Fy",
            "encode segment boundaries"
        );
    }
    #[test]
    fn rejects_unsafe_roots_but_accepts_loopback() {
        for value in [
            "file:///tmp/data",
            "http://example.test",
            "https://user:pass@example.test",
            "https://example.test/?token=x",
            "https://example.test/#x",
        ] {
            assert!(ApiEndpoint::parse(value).is_err(), "reject unsafe API root");
        }
        for value in ["http://localhost:8080", "http://127.0.0.1", "http://[::1]"] {
            assert!(ApiEndpoint::parse(value).is_ok(), "allow loopback HTTP");
        }
    }
}
