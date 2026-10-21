//! Verify complete HTTP observations survive late client disconnects without
//! hiding transport errors or treating incomplete responses as complete.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::mpsc,
};

use super::{
    BodyDirection, DecodedClientFlow, HookDispatcher, MitmTimeouts, forward_chunked_body,
    tests::test_flow,
};
use crate::{FlowOperation, HookFuture, HttpExchange, MitmHook, TransparentFlowError};

const HEAD: &[u8] = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
const PAYLOAD: &[u8] = b"data: [DONE]\n\n";

struct Observer(mpsc::UnboundedSender<HttpExchange>);

impl MitmHook for Observer {
    fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
        self.0.send(exchange.clone()).unwrap();
        Box::pin(std::future::ready(Ok(())))
    }
}

struct Stream {
    reads: VecDeque<Vec<u8>>,
    written: usize,
    fail_after: usize,
    error_kind: io::ErrorKind,
}

impl Stream {
    fn new(reads: Vec<Vec<u8>>, fail_after: usize, error_kind: io::ErrorKind) -> Self {
        Self {
            reads: reads.into(),
            written: 0,
            fail_after,
            error_kind,
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(bytes) = self.reads.front_mut() {
            let count = bytes.len().min(buffer.remaining());
            buffer.put_slice(&bytes[..count]);
            bytes.drain(..count);
            if bytes.is_empty() {
                self.reads.pop_front();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = bytes
            .len()
            .min(self.fail_after.checked_sub(self.written).unwrap());
        if count == 0 {
            return Poll::Ready(Err(self.error_kind.into()));
        }
        self.written = self.written.checked_add(count).unwrap();
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn relay_case(buffered: bool, complete: bool, error_kind: io::ErrorKind) {
    let chunk = [b"e\r\n".as_slice(), PAYLOAD, b"\r\n"].concat();
    let mut reads = vec![HEAD.to_vec(), chunk.clone()];
    if complete {
        reads.push(b"0\r\nX-Trailer: retained\r\n\r\n".to_vec());
    }
    if buffered {
        reads = vec![reads.concat()];
    }
    // For complete bodies, fail after one byte of the final write was accepted.
    // For incomplete bodies, fail part-way through the data chunk instead.
    let body_prefix = if complete { chunk.len() } else { 0 };
    let fail_after = HEAD
        .len()
        .checked_add(body_prefix)
        .unwrap()
        .checked_add(1)
        .unwrap();
    let client = Stream::new(
        vec![b"GET /events HTTP/1.1\r\nHost: gateway.example\r\n\r\n".to_vec()],
        fail_after,
        error_kind,
    );
    let upstream = Stream::new(reads, usize::MAX, io::ErrorKind::Other);
    let hooks = HookDispatcher::default();
    let (sender, mut events) = mpsc::unbounded_channel();
    hooks.push(Observer(sender));
    let timeouts = MitmTimeouts::default();
    let flow = DecodedClientFlow::from_http1(client, test_flow(), timeouts.clone())
        .await
        .unwrap();
    let result = flow.relay_to(upstream, &hooks, timeouts, 1024).await;
    let error = result.err().expect("client write must fail");
    assert!(
        matches!(
            &error,
            TransparentFlowError::Io {
                operation: FlowOperation::WriteAgentResponseBody,
                source,
            } if source.kind() == error_kind
        ),
        "unexpected error: {error:?}"
    );

    let observed = tokio::time::timeout(Duration::from_secs(1), events.recv()).await;
    if complete && error_kind != io::ErrorKind::Other {
        let exchange = observed.unwrap().unwrap();
        assert_eq!(exchange.response.body().bytes(), PAYLOAD);
        assert!(!exchange.response.body().truncated());
        assert!(events.try_recv().is_err(), "capture must be submitted once");
    } else {
        assert!(
            observed.is_err(),
            "failed/incomplete bodies must not be completed"
        );
    }
}

#[tokio::test]
async fn complete_chunked_capture_survives_client_close_and_retains_error() {
    for buffered in [false, true] {
        for kind in [io::ErrorKind::BrokenPipe, io::ErrorKind::ConnectionReset] {
            relay_case(buffered, true, kind).await;
        }
    }
}

#[tokio::test]
async fn incomplete_capture_and_unexpected_write_errors_still_fail() {
    for buffered in [false, true] {
        relay_case(buffered, false, io::ErrorKind::BrokenPipe).await;
        relay_case(buffered, true, io::ErrorKind::Other).await;
    }
}

#[tokio::test]
async fn late_close_counts_only_accepted_bytes_and_preserves_capture_limit() {
    for limit in [4, 1024] {
        let mut client = Stream::new(Vec::new(), 8, io::ErrorKind::BrokenPipe);
        let capture = Box::pin(forward_chunked_body(
            &mut tokio::io::empty(),
            &mut client,
            b"e\r\ndata: [DONE]\n\n\r\n0\r\n\r\n",
            limit,
            BodyDirection::Response,
        ))
        .await
        .unwrap();
        assert_eq!(capture.forwarded_bytes, 8);
        assert_eq!(capture.body.bytes(), &PAYLOAD[..limit.min(PAYLOAD.len())]);
        assert_eq!(capture.body.truncated(), limit < PAYLOAD.len());
        assert!(
            capture
                .agent_write_error
                .unwrap()
                .is_agent_connection_close()
        );
    }
}

#[tokio::test]
async fn provider_write_failure_never_becomes_a_completed_request() {
    let mut upstream = Stream::new(Vec::new(), 8, io::ErrorKind::BrokenPipe);
    let result = Box::pin(forward_chunked_body(
        &mut tokio::io::empty(),
        &mut upstream,
        b"e\r\ndata: [DONE]\n\n\r\n0\r\n\r\n",
        1024,
        BodyDirection::Request,
    ))
    .await;
    assert!(matches!(
        result,
        Err(TransparentFlowError::Io {
            operation: FlowOperation::WriteProviderRequestBody,
            ..
        })
    ));
}
