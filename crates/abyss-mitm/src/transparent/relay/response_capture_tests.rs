//! Verify complete HTTP observations survive late client disconnects without
//! hiding transport errors or treating incomplete responses as complete.

use std::{
    collections::VecDeque,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use futures_util::task::AtomicWaker;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Notify, mpsc},
};

use super::{DecodedClientFlow, HookDispatcher, MitmTimeouts, tests::test_flow};
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
    write_gate: Option<Arc<OperationGate>>,
    shutdown_gate: Option<Arc<OperationGate>>,
    shutdown_error: Option<io::ErrorKind>,
    flush_error: Option<io::ErrorKind>,
}

impl Stream {
    fn new(reads: Vec<Vec<u8>>, fail_after: usize, error_kind: io::ErrorKind) -> Self {
        Self {
            reads: reads.into(),
            written: 0,
            fail_after,
            error_kind,
            write_gate: None,
            shutdown_gate: None,
            shutdown_error: None,
            flush_error: None,
        }
    }
}

#[derive(Default)]
struct OperationGate {
    entered: Notify,
    released: AtomicBool,
    waker: AtomicWaker,
}

impl OperationGate {
    fn poll(&self, context: &Context<'_>) -> Poll<()> {
        self.waker.register(context.waker());
        if self.released.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            self.entered.notify_one();
            Poll::Pending
        }
    }

    fn release(&self) {
        self.released.store(true, Ordering::Release);
        self.waker.wake();
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
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let count = bytes
            .len()
            .min(self.fail_after.checked_sub(self.written).unwrap());
        if count == 0 {
            if self
                .write_gate
                .as_ref()
                .is_some_and(|gate| gate.poll(cx).is_pending())
            {
                return Poll::Pending;
            }
            if self.error_kind == io::ErrorKind::WriteZero {
                return Poll::Ready(Ok(0));
            }
            return Poll::Ready(Err(self.error_kind.into()));
        }
        self.written = self.written.checked_add(count).unwrap();
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.flush_error.map_or(Ok(()), |kind| Err(kind.into())))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self
            .shutdown_gate
            .as_ref()
            .is_some_and(|gate| gate.poll(cx).is_pending())
        {
            return Poll::Pending;
        }
        Poll::Ready(self.shutdown_error.map_or(Ok(()), |kind| Err(kind.into())))
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
    if complete {
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
        for kind in [
            io::ErrorKind::BrokenPipe,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::Other,
            io::ErrorKind::WriteZero,
        ] {
            relay_case(buffered, true, kind).await;
        }
    }
}

#[tokio::test]
async fn incomplete_capture_is_not_submitted() {
    for buffered in [false, true] {
        relay_case(buffered, false, io::ErrorKind::BrokenPipe).await;
    }
}

async fn start_relay(
    client: Stream,
    response_reads: Vec<Vec<u8>>,
    limit: usize,
) -> (
    tokio::task::JoinHandle<Result<super::RelayOutcome, TransparentFlowError>>,
    mpsc::UnboundedReceiver<HttpExchange>,
) {
    let upstream = Stream::new(response_reads, usize::MAX, io::ErrorKind::Other);
    let hooks = HookDispatcher::default();
    let (sender, events) = mpsc::unbounded_channel();
    hooks.push(Observer(sender));
    let timeouts = MitmTimeouts::default();
    let flow = DecodedClientFlow::from_http1(client, test_flow(), timeouts.clone())
        .await
        .unwrap();
    let relay = tokio::spawn(async move { flow.relay_to(upstream, &hooks, timeouts, limit).await });
    (relay, events)
}

fn client(fail_after: usize) -> Stream {
    Stream::new(
        vec![b"GET /events HTTP/1.1\r\nHost: gateway.example\r\n\r\n".to_vec()],
        fail_after,
        io::ErrorKind::BrokenPipe,
    )
}

#[tokio::test]
async fn hook_waits_for_final_client_write_before_observing_complete_body() {
    let chunk = [b"e\r\n".as_slice(), PAYLOAD, b"\r\n"].concat();
    let length_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        PAYLOAD.len()
    );
    for (reads, fail_after) in [
        (
            vec![HEAD.to_vec(), chunk.clone(), b"0\r\n\r\n".to_vec()],
            HEAD.len() + chunk.len(),
        ),
        (
            vec![length_head.as_bytes().to_vec(), PAYLOAD.to_vec()],
            length_head.len(),
        ),
    ] {
        let mut client = client(fail_after);
        let gate = Arc::new(OperationGate::default());
        client.write_gate = Some(gate.clone());
        let (relay, mut events) = start_relay(client, reads, 1024).await;
        tokio::time::timeout(Duration::from_secs(1), gate.entered.notified())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), events.recv())
                .await
                .is_err(),
            "hook must wait for the client write to finish"
        );
        assert!(!relay.is_finished());
        gate.release();
        assert!(matches!(
            relay.await.unwrap(),
            Err(TransparentFlowError::Io {
                operation: FlowOperation::WriteAgentResponseBody,
                ..
            })
        ));
        let exchange = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exchange.response.body().bytes(), PAYLOAD);
        assert!(events.try_recv().is_err(), "submit each exchange once");
    }
}

#[tokio::test]
async fn hook_waits_for_client_shutdown_before_observing_complete_body() {
    let gate = Arc::new(OperationGate::default());
    let mut client = client(usize::MAX);
    client.shutdown_gate = Some(gate.clone());
    client.shutdown_error = Some(io::ErrorKind::Other);
    let (relay, mut events) = start_relay(
        client,
        vec![b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()],
        1024,
    )
    .await;
    tokio::time::timeout(Duration::from_secs(1), gate.entered.notified())
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), events.recv())
            .await
            .is_err()
    );
    assert!(!relay.is_finished());
    gate.release();
    assert!(matches!(
        relay.await.unwrap(),
        Err(TransparentFlowError::Io {
            operation: FlowOperation::ShutdownAgent,
            ..
        })
    ));
    let exchange = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(exchange.response.body().bytes().is_empty());
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn content_length_capture_survives_final_write_failure_and_respects_limits() {
    let head = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        PAYLOAD.len()
    );
    for buffered in [false, true] {
        for limit in [4, 1024] {
            let reads = if buffered {
                vec![[head.as_bytes(), PAYLOAD].concat()]
            } else {
                vec![head.as_bytes().to_vec(), PAYLOAD.to_vec()]
            };
            let (relay, mut events) = start_relay(client(head.len() + 1), reads, limit).await;
            let result = relay.await.unwrap();
            assert!(matches!(
                result,
                Err(TransparentFlowError::Io {
                    operation: FlowOperation::WriteAgentResponseBody,
                    ..
                })
            ));
            let exchange = tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                exchange.response.body().bytes(),
                &PAYLOAD[..limit.min(PAYLOAD.len())]
            );
            assert_eq!(exchange.response.body().truncated(), limit < PAYLOAD.len());
            assert!(events.try_recv().is_err());
        }
    }
}

#[tokio::test]
async fn late_chunked_disconnect_keeps_the_capture_limit() {
    let chunk = [b"e\r\n".as_slice(), PAYLOAD, b"\r\n"].concat();
    let (relay, mut events) = start_relay(
        client(HEAD.len() + chunk.len()),
        vec![HEAD.to_vec(), chunk, b"0\r\n\r\n".to_vec()],
        4,
    )
    .await;
    assert!(relay.await.unwrap().is_err());
    let exchange = tokio::time::timeout(Duration::from_secs(1), events.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(exchange.response.body().bytes(), &PAYLOAD[..4]);
    assert!(exchange.response.body().truncated());
    assert!(events.try_recv().is_err());
}

#[tokio::test]
async fn failed_final_write_counts_only_accepted_wire_bytes() {
    for limit in [4, 1024] {
        let mut client = client(8);
        let capture = Box::pin(super::forward_chunked_body(
            &mut tokio::io::empty(),
            &mut client,
            b"e\r\ndata: [DONE]\n\n\r\n0\r\n\r\n",
            limit,
            super::BodyDirection::Response,
        ))
        .await
        .unwrap();
        assert_eq!(capture.forwarded_bytes, 8);
        assert_eq!(client.written, 8);
        assert_eq!(capture.body.bytes(), &PAYLOAD[..limit.min(PAYLOAD.len())]);
        assert_eq!(capture.body.truncated(), limit < PAYLOAD.len());
        assert!(
            matches!(capture.agent_write_error, Some(TransparentFlowError::Io {
            operation: FlowOperation::WriteAgentResponseBody, source,
        }) if source.kind() == io::ErrorKind::BrokenPipe)
        );
    }
}

#[tokio::test]
async fn request_forwarding_failure_still_returns_the_original_error() {
    let mut upstream = Stream::new(Vec::new(), 1, io::ErrorKind::BrokenPipe);
    let result = Box::pin(super::forward_chunked_body(
        &mut tokio::io::empty(),
        &mut upstream,
        b"e\r\ndata: [DONE]\n\n\r\n0\r\n\r\n",
        1024,
        super::BodyDirection::Request,
    ))
    .await;
    assert!(matches!(result, Err(TransparentFlowError::Io {
        operation: FlowOperation::WriteProviderRequestBody, source,
    }) if source.kind() == io::ErrorKind::BrokenPipe));
}

#[tokio::test]
async fn incomplete_or_invalid_response_is_never_submitted() {
    let length_head = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n";
    for (reads, fail_after) in [
        (
            vec![length_head.to_vec(), PAYLOAD.to_vec()],
            length_head.len() + 1,
        ),
        (vec![length_head.to_vec(), PAYLOAD.to_vec()], usize::MAX),
        (
            vec![
                HEAD.to_vec(),
                b"e\r\ndata: [DONE]\n\n\r\n0\r\n\r\npipelined".to_vec(),
            ],
            usize::MAX,
        ),
        (
            vec![
                HEAD.to_vec(),
                b"e\r\ndata: [DONE]\n\n\r\n0\r\nX-Trailer: incomplete".to_vec(),
            ],
            usize::MAX,
        ),
    ] {
        let (relay, mut events) = start_relay(client(fail_after), reads, 1024).await;
        assert!(relay.await.unwrap().is_err());
        assert!(
            tokio::time::timeout(Duration::from_secs(1), events.recv())
                .await
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn completed_empty_and_eof_responses_survive_cleanup_errors() {
    for (reads, body) in [
        (
            vec![b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()],
            b"".as_slice(),
        ),
        (
            vec![
                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec(),
                PAYLOAD.to_vec(),
            ],
            PAYLOAD,
        ),
    ] {
        let mut client = client(usize::MAX);
        client.shutdown_error = Some(io::ErrorKind::Other);
        let (relay, mut events) = start_relay(client, reads, 1024).await;
        assert!(matches!(
            relay.await.unwrap(),
            Err(TransparentFlowError::Io {
                operation: FlowOperation::ShutdownAgent,
                ..
            })
        ));
        let exchange = tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(exchange.response.body().bytes(), body);
        assert!(events.try_recv().is_err());
    }
    let mut client = client(usize::MAX);
    client.flush_error = Some(io::ErrorKind::BrokenPipe);
    let (relay, mut events) = start_relay(
        client,
        vec![b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()],
        1024,
    )
    .await;
    assert!(relay.await.unwrap().is_err());
    assert!(
        tokio::time::timeout(Duration::from_secs(1), events.recv())
            .await
            .unwrap()
            .is_some()
    );
}
