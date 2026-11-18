//! Applies explicit Agent actions to their original protocol locations.
//! No context diff, routing changes, or reconstruction from observation projections.

use std::collections::BTreeMap;

use abyss_mitm::{RequestEditor, RequestTransport, RequestView};
use abyss_plugin_protocol::inspection::{AgentRequestContext, ModifyAction};
use http::{HeaderName, HeaderValue};
use serde_json::Value;

use super::auth::AuthBinding;
use crate::protocol::{AnthropicProtocol, LlmProtocol, OpenAiProtocol, ProtocolDetector};

/// Safe error categories for plugin edits; action values are never echoed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RequestActionError {
    /// The selected credential is unknown or belongs to an established connection.
    #[error("Authentication actions are unavailable for this request")]
    AuthenticationUnavailable,
    /// There is no supported model write-back location.
    #[error("Model actions are unavailable for this request")]
    ModelUnavailable,
    /// The selected endpoint is unavailable at this forwarding boundary.
    #[error("Invalid provider endpoint for this request")]
    InvalidProvider,
    /// The token cannot be represented in the selected credential header.
    #[error("Invalid authentication token encoding")]
    InvalidToken,
    /// The edited document could not be encoded.
    #[error("Edited model request could not be encoded")]
    Encoding,
    /// The protocol variant is not implemented by this runtime.
    #[error("Unsupported request modification action")]
    UnsupportedAction,
}

/// Write-back locations fixed for one request's plugin chain.
pub struct RequestActions {
    auth: Option<AuthBinding>,
    auth_writable: bool,
    model: Option<ModelLocation>,
}

#[derive(Clone, Copy)]
enum ModelLocation {
    Root,
    Response,
}

impl ModelLocation {
    fn detect(request: &RequestView<'_>) -> Option<Self> {
        let document = request.body.json()?;
        let (location, payload) = if matches!(request.transport, RequestTransport::Http) {
            (Self::Root, document)
        } else {
            if document.get("type").and_then(Value::as_str) != Some("response.create") {
                return None;
            }
            document
                .get("response")
                .map_or((Self::Root, document), |payload| (Self::Response, payload))
        };
        if !payload.is_object() {
            return None;
        }
        let protocol = ProtocolDetector::detect_request(request.head.uri().path(), Some(payload))?;
        let supported = match request.transport {
            RequestTransport::Http => matches!(
                protocol,
                LlmProtocol::OpenAi(_) | LlmProtocol::Anthropic(AnthropicProtocol::Messages)
            ),
            _ => protocol == LlmProtocol::OpenAi(OpenAiProtocol::Responses),
        };
        supported.then_some(location)
    }

    fn object(
        self,
        document: &mut Value,
    ) -> Result<&mut serde_json::Map<String, Value>, RequestActionError> {
        let payload = match self {
            Self::Root => document,
            Self::Response => document
                .get_mut("response")
                .ok_or(RequestActionError::ModelUnavailable)?,
        };
        payload
            .as_object_mut()
            .ok_or(RequestActionError::ModelUnavailable)
    }
}

impl RequestActions {
    /// Resolves the current target and protocol without copying request content.
    #[must_use]
    pub fn new(request: &RequestView<'_>) -> Self {
        let auth = AuthBinding::detect(request);
        Self {
            auth,
            auth_writable: auth.is_some() && matches!(request.transport, RequestTransport::Http),
            model: ModelLocation::detect(request),
        }
    }

    /// Refreshes token visibility while preserving the chain's selected binding.
    pub fn annotate(&self, request: &RequestView<'_>, context: &mut AgentRequestContext) {
        context.auth_token = self
            .auth
            .and_then(|binding| binding.token(request.head.headers()))
            .map(str::to_owned);
        context.auth_token_writable = self.auth_writable;
        context.model_writable = self.model.is_some();
    }

    /// Applies the ordered list privately; callers discard the request on error.
    ///
    /// # Errors
    /// Returns a value-free error for unavailable or malformed actions.
    pub fn apply(
        &self,
        request: &mut RequestEditor<'_>,
        actions: Box<[ModifyAction]>,
    ) -> Result<(), RequestActionError> {
        let mut document = None;
        for action in actions {
            match action {
                ModifyAction::SetAuthToken(token) => {
                    let binding = self.writable_auth()?;
                    let value = binding
                        .encode(&token)
                        .map_err(|_| RequestActionError::InvalidToken)?;
                    request.headers_mut().insert(binding.header(), value);
                }
                ModifyAction::RouteProvider(endpoint) => {
                    let current = request.view();
                    let model_upgrade = current.head.method() == http::Method::GET
                        && current.head.uri().path().ends_with("/responses")
                        && current
                            .head
                            .headers()
                            .get(http::header::UPGRADE)
                            .is_some_and(|value| {
                                value.as_bytes().eq_ignore_ascii_case(b"websocket")
                            });
                    if !(model_upgrade
                        || current.head.method() == http::Method::POST && self.model.is_some())
                    {
                        return Err(RequestActionError::InvalidProvider);
                    }
                    request
                        .route_provider(&endpoint)
                        .map_err(|_| RequestActionError::InvalidProvider)?;
                }
                ModifyAction::SetAuthHeaders(values) => Self::set_auth_headers(request, values)?,
                ModifyAction::RemoveAuthToken => {
                    let binding = self.writable_auth()?;
                    request.headers_mut().remove(binding.header());
                }
                ModifyAction::SetModel(model) => {
                    self.model_object(request, &mut document)?
                        .insert("model".to_owned(), Value::String(model));
                }
                ModifyAction::RemoveModel => {
                    self.model_object(request, &mut document)?.remove("model");
                }
                _ => return Err(RequestActionError::UnsupportedAction),
            }
        }
        if let Some(document) = document {
            let bytes = serde_json::to_vec(&document).map_err(|_| RequestActionError::Encoding)?;
            request.replace_body(bytes.into());
        }
        Ok(())
    }

    fn set_auth_headers(
        request: &mut RequestEditor<'_>,
        values: BTreeMap<String, String>,
    ) -> Result<(), RequestActionError> {
        if !matches!(request.view().transport, RequestTransport::Http) {
            return Err(RequestActionError::AuthenticationUnavailable);
        }
        let headers = request.headers_mut();
        let previous: Box<[_]> = headers
            .keys()
            .filter(|name| {
                abyss_mitm::is_sensitive_header(name)
                    || headers.get_all(*name).iter().any(HeaderValue::is_sensitive)
            })
            .cloned()
            .collect();
        for name in previous {
            headers.remove(name);
        }
        for (name, value) in values {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| RequestActionError::InvalidToken)?;
            // Credential edits cannot change HTTP routing, framing or protocol negotiation.
            if matches!(
                name.as_str(),
                "host"
                    | "connection"
                    | "keep-alive"
                    | "proxy-authorization"
                    | "proxy-connection"
                    | "content-length"
                    | "transfer-encoding"
                    | "content-encoding"
                    | "content-type"
                    | "upgrade"
                    | "te"
                    | "trailer"
                    | "expect"
            ) || name.as_str().starts_with("sec-websocket-")
            {
                return Err(RequestActionError::InvalidToken);
            }
            let mut value =
                HeaderValue::from_str(&value).map_err(|_| RequestActionError::InvalidToken)?;
            value.set_sensitive(true);
            headers.insert(name, value);
        }
        Ok(())
    }

    fn writable_auth(&self) -> Result<AuthBinding, RequestActionError> {
        self.auth
            .filter(|_| self.auth_writable)
            .ok_or(RequestActionError::AuthenticationUnavailable)
    }

    fn model_object<'a>(
        &self,
        request: &RequestEditor<'_>,
        document: &'a mut Option<Value>,
    ) -> Result<&'a mut serde_json::Map<String, Value>, RequestActionError> {
        let location = self.model.ok_or(RequestActionError::ModelUnavailable)?;
        if document.is_none() {
            *document = request.view().body.json().cloned();
        }
        location.object(
            document
                .as_mut()
                .ok_or(RequestActionError::ModelUnavailable)?,
        )
    }
}
