//! Selected single-token authentication carriers for model request editing.
//! Existing credential headers identify compatible gateways; first-party hosts
//! also provide a binding when the client has not supplied a credential yet.

use abyss_mitm::RequestView;
use http::{
    HeaderMap, HeaderValue,
    header::{AUTHORIZATION, HeaderName},
};

use crate::protocol::shared::http::{flow_server_name, request_host};

#[derive(Clone, Copy)]
pub(super) enum AuthBinding {
    Bearer,
    ApiKey,
    AnthropicApiKey,
}

impl AuthBinding {
    pub(super) fn detect(request: &RequestView<'_>) -> Option<Self> {
        let headers = request.head.headers();
        let candidates = [Self::Bearer, Self::ApiKey, Self::AnthropicApiKey];
        let mut present = candidates
            .into_iter()
            .filter(|binding| headers.contains_key(binding.header()));
        if let Some(binding) = present.next() {
            return (present.next().is_none() && binding.token(headers).is_some())
                .then_some(binding);
        }
        let authority =
            request_host(headers, request.head.uri()).or_else(|| flow_server_name(request.flow))?;
        let authority = authority.parse::<http::uri::Authority>().ok()?;
        match authority
            .host()
            .trim_end_matches('.')
            .to_ascii_lowercase()
            .as_str()
        {
            "api.openai.com" | "chatgpt.com" => Some(Self::Bearer),
            "api.anthropic.com" => Some(Self::ApiKey),
            _ => None,
        }
    }

    pub(super) const fn header(self) -> HeaderName {
        match self {
            Self::Bearer => AUTHORIZATION,
            Self::ApiKey => HeaderName::from_static("x-api-key"),
            Self::AnthropicApiKey => HeaderName::from_static("anthropic-api-key"),
        }
    }

    pub(super) fn token(self, headers: &HeaderMap) -> Option<&str> {
        let value = headers.get(self.header())?.to_str().ok()?;
        match self {
            Self::Bearer => {
                let (scheme, token) = value.split_once(' ')?;
                scheme.eq_ignore_ascii_case("bearer").then_some(token)
            }
            Self::ApiKey | Self::AnthropicApiKey => Some(value),
        }
    }

    pub(super) fn encode(
        self,
        token: &str,
    ) -> Result<HeaderValue, http::header::InvalidHeaderValue> {
        match self {
            Self::Bearer => HeaderValue::from_str(&format!("Bearer {token}")),
            Self::ApiKey | Self::AnthropicApiKey => HeaderValue::from_str(token),
        }
    }
}
