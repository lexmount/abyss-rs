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
