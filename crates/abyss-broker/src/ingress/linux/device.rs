//! Bounded IP packet queues connecting Linux TUN IO to smoltcp.

use std::collections::VecDeque;

use smoltcp::{phy, time::Instant};

const PACKET_QUEUE_LIMIT: usize = 256;

/// A single-reader packet device; smoltcp owns checksum validation.
pub(super) struct PacketDevice {
    incoming: Option<Box<[u8]>>,
    pub(super) outgoing: VecDeque<Box<[u8]>>,
    mtu: usize,
}

impl PacketDevice {
    pub(super) const fn new(mtu: usize) -> Self {
        Self {
            incoming: None,
            outgoing: VecDeque::new(),
            mtu,
        }
    }

    pub(super) fn receive_packet(&mut self, packet: Box<[u8]>) {
        self.incoming = Some(packet);
    }
}

impl phy::Device for PacketDevice {
    type RxToken<'a> = RxToken;
    type TxToken<'a> = TxToken<'a>;

    fn capabilities(&self) -> phy::DeviceCapabilities {
        let mut capabilities = phy::DeviceCapabilities::default();
        capabilities.medium = phy::Medium::Ip;
        capabilities.max_transmission_unit = self.mtu;
        capabilities
    }

    fn receive(&mut self, _: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.outgoing.len() >= PACKET_QUEUE_LIMIT {
            return None;
        }
        self.incoming.take().map(|packet| {
            (
                RxToken(packet),
                TxToken {
                    queue: &mut self.outgoing,
                },
            )
        })
    }

    fn transmit(&mut self, _: Instant) -> Option<Self::TxToken<'_>> {
        (self.outgoing.len() < PACKET_QUEUE_LIMIT).then_some(TxToken {
            queue: &mut self.outgoing,
        })
    }
}

pub(super) struct RxToken(Box<[u8]>);

impl phy::RxToken for RxToken {
    fn consume<R, F>(self, consume: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        consume(&self.0)
    }
}

pub(super) struct TxToken<'a> {
    queue: &'a mut VecDeque<Box<[u8]>>,
}

impl phy::TxToken for TxToken<'_> {
    fn consume<R, F>(self, len: usize, consume: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len].into_boxed_slice();
        let result = consume(&mut packet);
        self.queue.push_back(packet);
        result
    }
}
