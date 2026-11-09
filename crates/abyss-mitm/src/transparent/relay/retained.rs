//! Bounded original wire-body storage for the shared framing pipeline.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::AsyncWrite;

pub(super) struct RetainedBody {
    pub(super) bytes: Vec<u8>,
    limit: usize,
}

impl RetainedBody {
    pub(super) const fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl AsyncWrite for RetainedBody {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "request exceeds inspection limit",
            )));
        }
        self.bytes.extend_from_slice(bytes);
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
