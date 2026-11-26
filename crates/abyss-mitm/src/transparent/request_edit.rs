//! Transport-only request edits held until synchronous processing succeeds.
//! Semantic action selection belongs to the broker and Agent protocol layer.

use bytes::Bytes;
use http::{Extensions, HeaderMap, Request, header};

use super::{CapturedBody, RequestTransport, RequestView};

/// Final replacements and observation annotations accepted before forwarding.
#[derive(Default)]
pub struct RequestForwardingResult {
    /// Replacement HTTP head; absent when the original head is retained.
    pub head: Option<Request<()>>,
    /// Replacement decoded body or WebSocket payload.
    pub body: Option<CapturedBody>,
    /// Parsing results for the final request.
    pub annotations: Extensions,
}

/// Borrowed original request with replacements allocated only when edited.
pub struct RequestEditor<'a> {
    original: RequestView<'a>,
    head: Option<Request<()>>,
    body: Option<CapturedBody>,
}

impl<'a> RequestEditor<'a> {
    /// Retains the original capture without cloning its JSON or byte contents.
    #[must_use]
    pub const fn new(original: RequestView<'a>) -> Self {
        Self {
            original,
            head: None,
            body: None,
        }
    }

    /// Current request seen by parsers and the next plugin.
    #[must_use]
    pub fn view(&self) -> RequestView<'_> {
        RequestView {
            flow: self.original.flow,
            head: self.head.as_ref().unwrap_or(self.original.head),
            body: self.body.as_ref().unwrap_or(self.original.body),
            transport: self.original.transport,
        }
    }

    /// Edits the current head without altering method, URI, or flow routing.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.head
            .get_or_insert_with(|| self.original.head.clone())
            .headers_mut()
    }

    /// Select the upstream hostname for this HTTP exchange, retaining scheme, port and path.
    /// The next connection uses the flow's existing proxy configuration.
    ///
    /// # Errors
    /// Rejects invalid DNS names and data frames on an established WebSocket.
    pub fn set_upstream_host(&mut self, host: &str) -> Result<(), &'static str> {
        if !matches!(self.original.transport, RequestTransport::Http) {
            return Err("cannot change upstream after WebSocket upgrade");
        }
        let target = super::RedirectTarget::parse(host)?;
        let head = self.head.get_or_insert_with(|| self.original.head.clone());
        let old_host = head.uri().host().or_else(|| {
            head.headers()
                .get(header::HOST)?
                .to_str()
                .ok()?
                .split(':')
                .next()
        });
        if old_host.is_some_and(|old| old.eq_ignore_ascii_case(target.host())) {
            return Ok(());
        }
        target
            .apply(head)
            .map_err(|_| "invalid request authority")?;
        // The rewritten authority goes on the wire. The relay reads this extension
        // after inspection to choose the connection for this request.
        let proxy = head
            .extensions_mut()
            .remove::<super::redirect::ExchangeRoute>()
            .and_then(|route| route.proxy);
        head.extensions_mut()
            .insert(super::redirect::ExchangeRoute {
                host: target,
                proxy,
            });
        // Rebuild cross-origin headers from wire-protocol fields. A later token action
        // can install the selected provider credential using the original carrier.
        let upgrading = super::utils::is_websocket_upgrade_request(head);
        let mut headers = HeaderMap::new();
        for (name, value) in head.headers() {
            if matches!(
                name.as_str(),
                "host"
                    | "accept"
                    | "accept-encoding"
                    | "content-type"
                    | "user-agent"
                    | "originator"
                    | "sec-websocket-version"
                    | "sec-websocket-key"
                    | "anthropic-version"
                    | "anthropic-beta"
                    | "openai-beta"
            ) {
                headers.append(name.clone(), value.clone());
            }
        }
        if upgrading {
            headers.insert(header::UPGRADE, http::HeaderValue::from_static("websocket"));
            headers.insert(
                header::CONNECTION,
                http::HeaderValue::from_static("upgrade"),
            );
        }
        *head.headers_mut() = headers;
        // Reframe the decoded payload, excluding trailers tied to the old authority.
        let bytes = self.view().body.bytes_ref().clone();
        self.replace_body(bytes);
        Ok(())
    }

    /// Select the account proxy even when the API hostname stays the same.
    ///
    /// # Errors
    /// Rejects invalid routes and changes to an established WebSocket.
    pub fn set_account_proxy(
        &mut self,
        account: &abyss_plugin_protocol::account_proxy::AccountProxy,
    ) -> Result<(), &'static str> {
        if !matches!(self.original.transport, RequestTransport::Http) {
            return Err("cannot change proxy after WebSocket upgrade");
        }
        let proxy = crate::outbound::UpstreamProxy::for_account(account)
            .map_err(|_| "invalid account proxy")?;
        let head = self.head.get_or_insert_with(|| self.original.head.clone());
        let authority = head
            .uri()
            .authority()
            .cloned()
            .or_else(|| {
                head.headers()
                    .get(header::HOST)?
                    .to_str()
                    .ok()?
                    .parse()
                    .ok()
            })
            .ok_or("missing request authority")?;
        let host = super::RedirectTarget::parse(authority.host())?;
        head.extensions_mut()
            .insert(super::redirect::ExchangeRoute {
                host,
                proxy: Some(proxy),
            });
        Ok(())
    }

    /// Replace only the path on an HTTP request or upgrade, retaining its raw query.
    ///
    /// # Errors
    /// Rejects non-path input and messages on an established WebSocket.
    pub fn set_request_path(&mut self, path: &str) -> Result<(), &'static str> {
        if !matches!(self.original.transport, RequestTransport::Http)
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.contains(['?', '#'])
        {
            return Err("Expected an absolute HTTP request path");
        }
        let uri = self.view().head.uri();
        let path_and_query = uri
            .query()
            .map_or_else(|| path.to_owned(), |q| format!("{path}?{q}"));
        let mut parts = uri.clone().into_parts();
        parts.path_and_query = Some(
            path_and_query
                .parse()
                .map_err(|_| "Invalid HTTP request path")?,
        );
        let uri = http::Uri::from_parts(parts).map_err(|_| "Invalid HTTP request URI")?;
        *self
            .head
            .get_or_insert_with(|| self.original.head.clone())
            .uri_mut() = uri;
        Ok(())
    }

    /// Installs identity-encoded content and resets obsolete body parsing state.
    pub fn replace_body(&mut self, bytes: Bytes) {
        if matches!(self.original.transport, RequestTransport::Http) {
            let headers = self.headers_mut();
            headers.remove(header::CONTENT_ENCODING);
            headers.remove(header::TRANSFER_ENCODING);
            headers.remove(header::TRAILER);
            headers.insert(header::CONTENT_LENGTH, bytes.len().into());
        }
        self.body = Some(CapturedBody::from_bytes(bytes));
    }

    /// Releases accepted replacements with typed data for later observation.
    #[must_use]
    pub fn finish<T: Clone + Send + Sync + 'static>(
        self,
        annotation: T,
    ) -> RequestForwardingResult {
        let mut annotations = Extensions::new();
        annotations.insert(annotation);
        RequestForwardingResult {
            head: self.head,
            body: self.body,
            annotations,
        }
    }
}
