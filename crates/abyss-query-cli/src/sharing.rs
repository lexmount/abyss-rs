//! Browser share links on the API origin; snapshot policy remains server-owned.

use abyss_data_client::{
    ApiEndpoint,
    models::{CreatedSessionShare, SessionShareSummary},
};
use reqwest::Url;
use schemars::JsonSchema;
use serde::Serialize;

use crate::error::QueryError as Error;

/// Explicit command output. The capability appears only inside the browser URL.
#[derive(Serialize, JsonSchema)]
pub struct SessionShareLink {
    pub url: String,
    pub share: SessionShareSummary,
}

impl SessionShareLink {
    pub fn new(endpoint: &ApiEndpoint, response: CreatedSessionShare) -> Result<Self, Error> {
        if response.token.is_empty() {
            return Err(Error::Protocol(
                "share response contains an empty capability",
            ));
        }
        let mut url =
            Url::parse(endpoint.as_str()).map_err(|_| Error::Config("invalid API endpoint"))?;
        // API and browser routes share an origin. The share route is rooted at
        // the site root, so an API prefix such as /api/ must not carry over.
        url.set_path(&format!("/shared/sessions/{}", response.share.id));
        // Match URLSearchParams in the web client, encoding token delimiters.
        url.query_pairs_mut().append_pair("token", &response.token);
        let fragment = url.query().map(str::to_owned);
        url.set_query(None);
        url.set_fragment(fragment.as_deref());
        Ok(Self {
            url: url.into(),
            share: response.share,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::SessionShareLink;
    use abyss_data_client::{ApiEndpoint, models::CreatedSessionShare};
    use reqwest::Url;
    use serde_json::json;

    fn response(token: &str) -> CreatedSessionShare {
        serde_json::from_value(json!({
            "share": {"id":"11111111-1111-4111-8111-111111111111",
                "created_at":"2026-01-01T00:00:00Z", "snapshot_at":"2026-01-01T00:00:00Z",
                "expires_at":"2026-01-08T00:00:00Z", "revoked_at":null, "status":"active"},
            "token": token
        }))
        .expect("share fixture")
    }

    #[test]
    fn uses_api_origin_and_encodes_capability_only_in_fragment() {
        for (api, origin) in [
            ("https://example.test/api", "https://example.test"),
            ("https://example.test/api/", "https://example.test"),
            ("https://example.test/", "https://example.test"),
            ("https://example.test/a%20b/api/", "https://example.test"),
            (
                "https://example.test:8443/api/",
                "https://example.test:8443",
            ),
            ("http://127.0.0.1:8080/api/", "http://127.0.0.1:8080"),
            ("http://[::1]:8080/api/", "http://[::1]:8080"),
        ] {
            let link = SessionShareLink::new(
                &ApiEndpoint::parse(api).expect("API endpoint"),
                response("a+ b&c=#/?"),
            )
            .expect("link");
            assert_eq!(
                link.url,
                format!(
                    "{origin}/shared/sessions/11111111-1111-4111-8111-111111111111#token=a%2B+b%26c%3D%23%2F%3F"
                ),
                "preserve origin and replace API path"
            );
            let url = Url::parse(&link.url).expect("URL");
            assert!(url.query().is_none(), "no capability in HTTP query");
            let output = serde_json::to_value(link).expect("output");
            assert!(output.get("token").is_none(), "do not duplicate capability");
            assert_eq!(output["share"]["status"], "active", "retain server summary");
        }
    }

    #[test]
    fn rejects_empty_capabilities() {
        let endpoint = ApiEndpoint::parse("http://127.0.0.1:8080/api/").expect("endpoint");
        assert!(
            SessionShareLink::new(&endpoint, response("")).is_err(),
            "reject unusable capability"
        );
    }
}
