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

/// An edit that cannot fit the existing transport body budget.
#[derive(Debug, thiserror::Error)]
#[error("Edited request exceeds the forwarding limit")]
pub struct RequestEditTooLarge;

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
            max_body_bytes: self.original.max_body_bytes,
        }
    }

    /// Edits the current head without altering method, URI, or flow routing.
    pub fn headers_mut(&mut self) -> &mut HeaderMap {
        self.head
            .get_or_insert_with(|| self.original.head.clone())
            .headers_mut()
    }

    /// Installs identity-encoded content and resets obsolete body parsing state.
    ///
    /// # Errors
    /// Returns an error when the replacement exceeds the forwarding limit.
    pub fn replace_body(&mut self, bytes: Bytes) -> Result<(), RequestEditTooLarge> {
        if bytes.len() > self.original.max_body_bytes {
            return Err(RequestEditTooLarge);
        }
        if matches!(self.original.transport, RequestTransport::Http) {
            let headers = self.headers_mut();
            headers.remove(header::CONTENT_ENCODING);
            headers.remove(header::TRANSFER_ENCODING);
            headers.remove(header::TRAILER);
            headers.insert(header::CONTENT_LENGTH, bytes.len().into());
        }
        self.body = Some(CapturedBody::from_bytes(bytes));
        Ok(())
    }

    /// Checks the HTTP head budget after applying a list of header/body edits.
    ///
    /// # Errors
    /// Returns an error when the encoded head would exceed the decoder's limit.
    pub fn validate_head(&self) -> Result<(), RequestEditTooLarge> {
        let Some(head) = &self.head else {
            return Ok(());
        };
        let target_len = head
            .uri()
            .path_and_query()
            .map_or(1, |target| target.as_str().len());
        let length = head.headers().iter().fold(
            head.method()
                .as_str()
                .len()
                .saturating_add(target_len)
                .saturating_add(14),
            |size, (name, value)| {
                size.saturating_add(name.as_str().len())
                    .saturating_add(value.as_bytes().len())
                    .saturating_add(4)
            },
        );
        if length > crate::http1::MAX_HTTP1_HEADER_BYTES {
            return Err(RequestEditTooLarge);
        }
        Ok(())
    }

    /// Releases only the accepted replacements to the transport writer.
    #[must_use]
    pub fn finish(self, annotations: Extensions) -> RequestForwardingResult {
        RequestForwardingResult {
            head: self.head,
            body: self.body,
            annotations,
        }
    }
}
