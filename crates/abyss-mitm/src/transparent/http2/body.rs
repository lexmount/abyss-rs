//! Flow-controlled HTTP/2 bodies and bounded observation capture.

use std::{future::poll_fn, task::Poll};

use bytes::Bytes;
use h2::{RecvStream, SendStream};
use http::HeaderMap;

use super::super::{CapturedBody, content_encoding::ContentDecoder};

/// Retains only a prefix while all DATA and trailing headers continue on the wire.
pub(super) struct BodyCapture {
    bytes: Vec<u8>,
    limit: usize,
    truncated: bool,
}

impl BodyCapture {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            truncated: false,
        }
    }

    pub(super) fn append(&mut self, bytes: &[u8]) {
        let retained = bytes.len().min(self.limit.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..retained]);
        self.truncated |= retained < bytes.len();
    }

    pub(super) fn finish(self, headers: &HeaderMap) -> CapturedBody {
        let mut body = if self.truncated {
            CapturedBody::from_truncated_bytes(self.bytes.into())
        } else {
            CapturedBody::from_bytes(self.bytes.into())
        }
        .with_decode_limit(self.limit);
        ContentDecoder::prepare_body(headers, &mut body);
        body
    }

    pub(super) async fn relay(
        mut self,
        mut source: RecvStream,
        mut destination: SendStream<Bytes>,
        headers: &HeaderMap,
    ) -> Result<CapturedBody, h2::Error> {
        while let Some(chunk) = poll_fn(|cx| {
            if let Poll::Ready(reset) = destination.poll_reset(cx) {
                return Poll::Ready(Some(Err(reset
                    .err()
                    .unwrap_or_else(|| h2::Reason::CANCEL.into()))));
            }
            source.poll_data(cx)
        })
        .await
        {
            let chunk = chunk?;
            let length = chunk.len();
            self.append(&chunk);
            send_data(&mut destination, chunk).await?;
            // Release receive capacity only after downstream has accepted the bytes.
            // Otherwise a slow receiver could accumulate an unbounded relay queue.
            source.flow_control().release_capacity(length)?;
        }
        if let Some(trailers) = source.trailers().await? {
            destination.send_trailers(trailers)?;
        } else {
            destination.send_data(Bytes::new(), true)?;
        }
        Ok(self.finish(headers))
    }
}

pub(in crate::transparent) async fn send_data(
    stream: &mut SendStream<Bytes>,
    mut bytes: Bytes,
) -> Result<(), h2::Error> {
    while !bytes.is_empty() {
        stream.reserve_capacity(bytes.len());
        let capacity = poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .ok_or_else(|| h2::Error::from(h2::Reason::CANCEL))??;
        let length = capacity.min(bytes.len());
        stream.send_data(bytes.split_to(length), false)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_limit_marks_only_observation_as_truncated() {
        let mut capture = BodyCapture::new(3);
        capture.append(b"ab");
        capture.append(b"cdef");
        let body = capture.finish(&HeaderMap::new());
        assert_eq!(body.raw_bytes(), b"abc");
        assert!(
            body.raw_truncated(),
            "excess bytes must mark the capture incomplete"
        );
    }

    #[test]
    fn exact_limit_and_empty_bodies_are_complete() {
        for (limit, bytes) in [(0, &b""[..]), (3, &b"abc"[..])] {
            let mut capture = BodyCapture::new(limit);
            capture.append(bytes);
            let body = capture.finish(&HeaderMap::new());
            assert_eq!(body.raw_bytes(), bytes);
            assert!(!body.raw_truncated(), "an exact fit is complete");
        }
    }
}
