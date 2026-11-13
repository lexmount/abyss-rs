//! Counts decrypted HTTP/2 wire bytes without retaining frame contents.

use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(super) struct CountedIo<S> {
    stream: S,
    written_bytes: Arc<AtomicU64>,
}

impl<S> CountedIo<S> {
    pub(super) const fn new(stream: S, written_bytes: Arc<AtomicU64>) -> Self {
        Self {
            stream,
            written_bytes,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountedIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountedIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write(cx, bytes);
        if let Poll::Ready(Ok(written)) = &result {
            this.written_bytes.fetch_add(
                u64::try_from(*written).unwrap_or(u64::MAX),
                Ordering::Relaxed,
            );
        }
        result
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
