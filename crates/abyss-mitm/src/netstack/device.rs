//! Bounded asynchronous IP-packet transport shared by TUN and `WireGuard` stacks.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, Stream};
use tokio::sync::mpsc;
use tokio_smoltcp::{
    device::{AsyncDevice, DeviceCapabilities},
    smoltcp::phy::Medium,
};
use tokio_util::sync::{PollSendError, PollSender};

/// A channel-backed IP device with bounded queues supplied by its transport.
/// Packet ownership uses `Vec` because smoltcp's `AsyncDevice` requires it.
pub struct PacketDevice {
    incoming: mpsc::Receiver<io::Result<Vec<u8>>>,
    outgoing: PollSender<Vec<u8>>,
    capabilities: DeviceCapabilities,
}

impl PacketDevice {
    /// Uses the supplied channel capacities for backpressure and preserves IP checksums.
    #[must_use]
    pub fn new(
        incoming: mpsc::Receiver<io::Result<Vec<u8>>>,
        outgoing: mpsc::Sender<Vec<u8>>,
        mtu: usize,
    ) -> Self {
        // This external type is non-exhaustive and exposes fields, not setters.
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ip;
        capabilities.max_transmission_unit = mtu;
        capabilities.max_burst_size = Some(32);
        Self {
            incoming,
            outgoing: PollSender::new(outgoing),
            capabilities,
        }
    }
}

impl Stream for PacketDevice {
    type Item = io::Result<Vec<u8>>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.incoming.poll_recv(cx)
    }
}

impl Sink<Vec<u8>> for PacketDevice {
    type Error = io::Error;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outgoing.poll_reserve(cx).map_err(closed)
    }

    fn start_send(mut self: Pin<&mut Self>, packet: Vec<u8>) -> io::Result<()> {
        self.outgoing.send_item(packet).map_err(closed)
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.outgoing.close();
        Poll::Ready(Ok(()))
    }
}

impl AsyncDevice for PacketDevice {
    fn capabilities(&self) -> &DeviceCapabilities {
        &self.capabilities
    }
}

fn closed(_: PollSendError<Vec<u8>>) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "IP packet transport closed")
}
