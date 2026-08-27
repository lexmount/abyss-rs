//! Duplex byte stream abstractions used by transparent flow handling.
//!
//! Platform ingress implementations may receive bytes from TCP sockets, IPC
//! transports, or framed flow adapters. The MITM pipeline needs a TCP-like
//! asynchronous byte stream, not a concrete socket type.

use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Async byte stream accepted from a platform ingress.
pub trait DuplexStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> DuplexStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

/// Direction of bytes observed on a proxied flow.
#[derive(Debug, Clone, Copy, PartialEq)]
#[non_exhaustive]
pub enum TrafficDirection {
    /// Bytes read from the local client and sent toward the upstream service.
    ClientToUpstream,
    /// Bytes read from the upstream service and sent toward the local client.
    UpstreamToClient,
}

/// Lightweight observer for byte counts emitted by the shared MITM pipeline.
///
/// The observer is deliberately limited to direction and byte count. It does
/// not receive payload data, so broker telemetry cannot accidentally retain
/// prompt, response, cookie, or authorization content.
pub trait TrafficObserver: Send + Sync {
    /// Records bytes read from one side of a proxied flow.
    fn record_bytes(&self, direction: TrafficDirection, bytes: usize);
}

/// Duplex stream wrapper that observes bytes as they are read from one side of
/// a proxied flow.
pub(super) struct ObservedStream<S> {
    inner: S,
    observer: Arc<dyn TrafficObserver>,
    direction: TrafficDirection,
}

impl<S> ObservedStream<S> {
    /// Wraps a stream and records successful reads in the supplied direction.
    pub(super) fn new(
        inner: S,
        observer: Arc<dyn TrafficObserver>,
        direction: TrafficDirection,
    ) -> Self {
        Self {
            inner,
            observer,
            direction,
        }
    }
}

impl<S> AsyncRead for ObservedStream<S>
where
    S: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(&result, Poll::Ready(Ok(()))) {
            let bytes = buffer.filled().len().saturating_sub(before);
            if bytes > 0 {
                self.observer.record_bytes(self.direction, bytes);
            }
        }
        result
    }
}

impl<S> AsyncWrite for ObservedStream<S>
where
    S: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// Boxed platform byte stream used at broker/core boundaries.
pub type BoxedDuplexStream = Box<dyn DuplexStream>;

/// Duplex stream that replays already-read client bytes before reading inner IO.
pub struct PrefixedDuplexStream {
    prefix: Box<[u8]>,
    prefix_offset: usize,
    inner: BoxedDuplexStream,
}

impl PrefixedDuplexStream {
    /// Creates a duplex stream with a read prefix.
    #[must_use]
    pub const fn new(prefix: Box<[u8]>, inner: BoxedDuplexStream) -> Self {
        Self {
            prefix,
            prefix_offset: 0,
            inner,
        }
    }

    /// Boxes this prefixed stream as a generic duplex stream.
    #[must_use]
    pub fn boxed(self) -> BoxedDuplexStream {
        Box::new(self)
    }

    fn remaining_prefix(&self) -> &[u8] {
        &self.prefix[self.prefix_offset..]
    }

    const fn advance_prefix(&mut self, count: usize) {
        self.prefix_offset = self
            .prefix_offset
            .checked_add(count)
            .expect("prefix offset should not overflow");
    }
}

impl AsyncRead for PrefixedDuplexStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.remaining_prefix().is_empty() {
            let copy_len = buffer.remaining().min(self.remaining_prefix().len());
            buffer.put_slice(&self.remaining_prefix()[..copy_len]);
            self.advance_prefix(copy_len);
            return Poll::Ready(Ok(()));
        }

        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for PrefixedDuplexStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, duplex};

    use super::{ObservedStream, PrefixedDuplexStream, TrafficDirection, TrafficObserver};

    #[derive(Default)]
    struct RecordingObserver(Mutex<Vec<(TrafficDirection, usize)>>);

    impl TrafficObserver for RecordingObserver {
        fn record_bytes(&self, direction: TrafficDirection, bytes: usize) {
            self.0
                .lock()
                .expect("observer mutex should not be poisoned")
                .push((direction, bytes));
        }
    }

    #[tokio::test]
    async fn prefixed_duplex_stream_replays_prefix_before_inner_stream() {
        let (mut client, server) = duplex(64);
        client
            .write_all(b"inner")
            .await
            .expect("inner bytes should write");
        let mut stream = PrefixedDuplexStream::new(Box::from(&b"prefix-"[..]), Box::new(server));

        let mut buffer = [0_u8; 12];
        stream
            .read_exact(&mut buffer)
            .await
            .expect("prefixed stream should read");

        assert_eq!(&buffer, b"prefix-inner");
    }

    #[tokio::test]
    async fn observed_stream_records_successful_reads_without_observing_writes() {
        let (mut client, server) = duplex(64);
        client
            .write_all(b"hello")
            .await
            .expect("client bytes should write");
        let observer = Arc::new(RecordingObserver::default());
        let mut stream =
            ObservedStream::new(server, observer.clone(), TrafficDirection::ClientToUpstream);
        let mut buffer = [0_u8; 5];
        stream
            .read_exact(&mut buffer)
            .await
            .expect("observed stream should read");

        assert_eq!(&buffer, b"hello");
        assert_eq!(
            *observer
                .0
                .lock()
                .expect("observer mutex should not be poisoned"),
            vec![(TrafficDirection::ClientToUpstream, 5)]
        );
    }
}
