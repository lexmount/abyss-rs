//! A duplex stream that retains the resources required to keep its transport alive.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Keeps an owning transport guard alive for the complete application stream.
/// The stream drops before its owner so socket cleanup can still use that owner.
pub struct OwnedStream<S, O> {
    stream: S,
    _owner: O,
}

impl<S, O> OwnedStream<S, O> {
    /// Transfers both the stream and its lifetime guard into one IO value.
    #[must_use]
    pub const fn new(stream: S, owner: O) -> Self {
        Self {
            stream,
            _owner: owner,
        }
    }
}

impl<S: AsyncRead + Unpin, O: Unpin> AsyncRead for OwnedStream<S, O> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin, O: Unpin> AsyncWrite for OwnedStream<S, O> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
