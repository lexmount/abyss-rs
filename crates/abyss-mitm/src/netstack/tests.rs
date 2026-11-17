//! Shared packet-channel and transport-owner lifecycle regression tests.

use std::{io, sync::Arc};

use futures_util::{FutureExt as _, SinkExt as _, StreamExt as _};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    sync::mpsc,
};
use tokio_smoltcp::device::AsyncDevice as _;

use super::{OwnedStream, PacketDevice};

#[tokio::test]
async fn packet_queues_preserve_bytes_errors_and_backpressure() {
    let (input, incoming) = mpsc::channel(1);
    let (outgoing, mut output) = mpsc::channel(1);
    let mut device = PacketDevice::new(incoming, outgoing, 1400);
    assert_eq!(device.capabilities().max_transmission_unit, 1400);
    input.send(Ok(vec![1, 2, 3])).await.unwrap();
    assert_eq!(device.next().await.unwrap().unwrap(), [1, 2, 3]);
    input
        .send(Err(io::Error::other("input failed")))
        .await
        .unwrap();
    assert!(
        device.next().await.unwrap().is_err(),
        "input errors must reach the reactor"
    );
    device.send(vec![4, 5]).await.unwrap();
    let mut blocked = Box::pin(device.send(vec![6]));
    assert!(
        blocked.as_mut().now_or_never().is_none(),
        "full output queue must apply backpressure"
    );
    assert_eq!(output.recv().await.unwrap(), [4, 5]);
    blocked.await.unwrap();
    assert_eq!(output.recv().await.unwrap(), [6]);
    drop(output);
    assert_eq!(
        device.send(vec![7]).await.unwrap_err().kind(),
        io::ErrorKind::BrokenPipe
    );
    drop(input);
    assert!(
        device.next().await.is_none(),
        "input EOF must terminate the packet stream"
    );
}

#[tokio::test]
async fn owned_stream_preserves_half_close_and_releases_its_owner() {
    let owner = Arc::new(());
    let weak = Arc::downgrade(&owner);
    let (stream, mut peer) = tokio::io::duplex(32);
    let mut guarded = OwnedStream::new(stream, owner);
    guarded.write_all(b"request").await.unwrap();
    guarded.flush().await.unwrap();
    guarded.shutdown().await.unwrap();
    let mut request = Vec::new();
    peer.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");
    peer.write_all(b"response").await.unwrap();
    peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    guarded.read_to_end(&mut response).await.unwrap();
    assert_eq!(
        response, b"response",
        "read remains available after write shutdown"
    );
    assert!(
        weak.upgrade().is_some(),
        "transport owner must outlive stream IO"
    );
    drop(guarded);
    assert!(
        weak.upgrade().is_none(),
        "closing the last stream releases its owner"
    );
}
