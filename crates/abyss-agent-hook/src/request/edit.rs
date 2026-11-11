//! Applies explicit Agent actions to their original protocol locations.
//! No context diff or reconstruction from observation projections.

use abyss_mitm::{RequestEditor, RequestTransport, RequestView};
use abyss_plugin_protocol::inspection::{AgentRequestContext, ModifyAction};
use serde_json::Value;

use super::{auth::AuthBinding, endpoint::ModelEndpoint};
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
    /// The token cannot be represented in the selected credential header.
    #[error("Invalid authentication token encoding")]
    InvalidToken,
    /// The request has no editable model endpoint, or its connection is established.
    #[error("Base URL actions are unavailable for this request")]
    BaseUrlUnavailable,
    /// Model API base URLs need an HTTP(S) authority and optional path prefix.
    #[error("Invalid model API base URL")]
    InvalidBaseUrl,
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
    endpoint: Option<ModelEndpoint>,
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
            endpoint: ModelEndpoint::detect(request),
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
        context.base_url = self
            .endpoint
            .as_ref()
            .and_then(|endpoint| endpoint.base_url(request));
        context.base_url_writable =
            self.endpoint.is_some() && matches!(request.transport, RequestTransport::Http);
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
                ModifyAction::SetBaseUrl(base_url) => {
                    let view = request.view();
                    if !matches!(view.transport, RequestTransport::Http) {
                        return Err(RequestActionError::BaseUrlUnavailable);
                    }
                    let endpoint = self
                        .endpoint
                        .as_ref()
                        .ok_or(RequestActionError::BaseUrlUnavailable)?;
                    let (uri, authority) = endpoint.target(&base_url, view.head.uri().query())?;
                    request.set_upstream(uri, authority);
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
