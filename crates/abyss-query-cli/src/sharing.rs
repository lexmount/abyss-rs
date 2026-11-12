//! Browser share links; server authorization and snapshot policy remain remote.

use abyss_data_client::{
    ApiEndpoint,
    models::{CreatedSessionShare, SessionShareSummary},
};
use reqwest::Url;
use schemars::JsonSchema;
use serde::Serialize;

use crate::error::QueryError as Error;

/// Explicit frontend root, independent of the profile's data API location.
pub struct WebRoot(Url);

impl WebRoot {
    pub fn parse(value: &str, allow_http: bool) -> Result<Self, Error> {
        // Reuse the endpoint's scheme, credential, query and fragment policy.
        let endpoint = ApiEndpoint::parse_with_http(value, allow_http).map_err(|_| {
            Error::Config("web URL must be an absolute HTTPS root (HTTP on loopback or with --allow-http), without credentials, query or fragment")
        })?;
        Ok(Self(
            Url::parse(endpoint.as_str()).map_err(|_| Error::Config("invalid web URL"))?,
        ))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    fn share_url(&self, response: &CreatedSessionShare) -> Result<String, Error> {
        if response.token.is_empty() {
            return Err(Error::Protocol(
                "share response contains an empty capability",
            ));
        }
        let mut url = self.0.clone();
        url.path_segments_mut()
            .map_err(|()| Error::Config("web URL cannot contain path segments"))?
            .pop_if_empty()
            .extend(["shared", "sessions", &response.share.id.to_string()]);
        // Match URLSearchParams in the web client, encoding token delimiters.
        url.query_pairs_mut().append_pair("token", &response.token);
        let fragment = url.query().map(str::to_owned);
        url.set_query(None);
        url.set_fragment(fragment.as_deref());
        Ok(url.into())
    }
}

/// Explicit command output. The capability appears only inside the browser URL.
#[derive(Serialize, JsonSchema)]
pub struct SessionShareLink {
    pub url: String,
    pub share: SessionShareSummary,
}

impl SessionShareLink {
    pub fn new(root: &WebRoot, response: CreatedSessionShare) -> Result<Self, Error> {
        Ok(Self {
            url: root.share_url(&response)?,
            share: response.share,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionShareLink, WebRoot};
    use abyss_data_client::models::CreatedSessionShare;
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
    fn preserves_frontend_prefix_and_encodes_capability_only_in_fragment() {
        for root in ["https://web.example/a%20b", "https://web.example/a%20b/"] {
            let link = SessionShareLink::new(
                &WebRoot::parse(root, false).expect("root"),
                response("a+ b&c=#/?"),
            )
            .expect("link");
            let url = Url::parse(&link.url).expect("URL");
            assert_eq!(
                url.path(),
                "/a%20b/shared/sessions/11111111-1111-4111-8111-111111111111",
                "preserve router prefix"
            );
            assert!(url.query().is_none(), "no capability in HTTP query");
            assert_eq!(
                url.fragment(),
                Some("token=a%2B+b%26c%3D%23%2F%3F"),
                "encode exactly as URLSearchParams"
            );
            let output = serde_json::to_value(link).expect("output");
            assert!(output.get("token").is_none(), "do not duplicate capability");
            assert_eq!(output["share"]["status"], "active", "retain server summary");
        }
    }

    #[test]
    fn rejects_unsafe_roots_and_empty_capabilities() {
        for root in [
            "/app",
            "javascript:alert(1)",
            "https://user:password@example.test",
            "https://example.test/?token=x",
            "https://example.test/#token=x",
            "http://example.test",
        ] {
            assert!(
                WebRoot::parse(root, false).is_err(),
                "reject unsafe web root"
            );
        }
        assert!(
            WebRoot::parse("http://example.test/app", true).is_ok(),
            "explicit HTTP opt-in"
        );
        let root = WebRoot::parse("http://127.0.0.1:8080", false).expect("loopback");
        assert!(
            SessionShareLink::new(&root, response("")).is_err(),
            "reject unusable capability"
        );
    }
}
