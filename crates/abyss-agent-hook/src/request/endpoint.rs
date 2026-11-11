//! Model API base URLs retain the existing protocol operation and query.
//! This module selects HTTP targets; it does not translate provider payloads.

use abyss_mitm::{RequestView, TransparentProtocol};
use http::{HeaderValue, Uri};

use super::RequestActionError;
use crate::protocol::shared::http::flow_server_name;

pub(super) struct ModelEndpoint {
    operation: String,
}

impl ModelEndpoint {
    pub(super) fn detect(request: &RequestView<'_>) -> Option<Self> {
        let path = request.head.uri().path();
        ["/responses", "/chat/completions", "/messages"]
            .into_iter()
            .filter_map(|operation| {
                let start = path.rfind(operation)?;
                let suffix = &path[start..];
                (suffix == operation || suffix.starts_with(&format!("{operation}/")))
                    .then_some((start, suffix))
            })
            .max_by_key(|(start, _)| *start)
            .map(|(_, suffix)| Self {
                operation: suffix.to_owned(),
            })
    }

    pub(super) fn base_url(&self, request: &RequestView<'_>) -> Option<String> {
        let uri = request.head.uri();
        let authority = uri
            .authority()
            .map(ToString::to_string)
            .or_else(|| {
                request
                    .head
                    .headers()
                    .get(http::header::HOST)?
                    .to_str()
                    .ok()
                    .map(str::to_owned)
            })
            .or_else(|| flow_server_name(request.flow))?;
        let scheme = uri.scheme_str().unwrap_or(match request.flow.protocol {
            TransparentProtocol::PlainHttp => "http",
            _ => "https",
        });
        let prefix = uri.path().strip_suffix(&self.operation)?;
        Some(format!("{scheme}://{authority}{prefix}"))
    }

    pub(super) fn target(
        &self,
        base_url: &str,
        query: Option<&str>,
    ) -> Result<(Uri, HeaderValue), RequestActionError> {
        let base: Uri = base_url
            .parse()
            .map_err(|_| RequestActionError::InvalidBaseUrl)?;
        let authority = base.authority().ok_or(RequestActionError::InvalidBaseUrl)?;
        if !matches!(base.scheme_str(), Some("http" | "https"))
            || authority.as_str().contains('@')
            || (authority.as_str() != authority.host()
                && authority.port_u16().is_none_or(|port| port == 0))
            || base.query().is_some()
            || base_url.contains('#')
        {
            return Err(RequestActionError::InvalidBaseUrl);
        }
        let mut path = format!("{}{}", base.path().trim_end_matches('/'), self.operation);
        if let Some(query) = query {
            path.push('?');
            path.push_str(query);
        }
        let uri = Uri::builder()
            .scheme(
                base.scheme()
                    .cloned()
                    .ok_or(RequestActionError::InvalidBaseUrl)?,
            )
            .authority(authority.clone())
            .path_and_query(path)
            .build()
            .map_err(|_| RequestActionError::InvalidBaseUrl)?;
        let header = HeaderValue::from_str(authority.as_str())
            .map_err(|_| RequestActionError::InvalidBaseUrl)?;
        Ok((uri, header))
    }
}
