//! Bounded TUN flow admission and packet routing into the shared async TCP stack.
//!
//! Each live flow owns a tokio-smoltcp Net at its original destination. This
//! avoids retaining listeners for arbitrary target addresses after flows end.
//! TCP state, retransmission and byte-stream IO remain library-owned.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Weak},
    time::Duration,
};

use abyss_mitm::netstack::{OwnedStream, PacketDevice};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinSet,
};
use tokio_smoltcp::{
    Net, NetConfig,
    smoltcp::{
        iface::Config,
        wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket},
    },
};

const SOCKET_LIMIT: usize = 256;
const INPUT_QUEUE_LIMIT: usize = 32;
pub(super) const PACKET_QUEUE_LIMIT: usize = 256;
const STREAM_BUFFER_SIZE: usize = 0x0001_0000;
const ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);

/// Both endpoints identify a client TCP connection independently of its target.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub(super) struct FlowKey {
    pub(super) source: SocketAddr,
    pub(super) destination: SocketAddr,
}

struct PacketHeader {
    key: FlowKey,
    opening: bool,
}

impl PacketHeader {
    fn parse(packet: &[u8]) -> Option<Self> {
        let version = packet.first()?.checked_shr(4)?;
        let (source, destination, payload, checksum_valid) = match version {
            4 => {
                let ip = Ipv4Packet::new_checked(packet).ok()?;
                if ip.next_header() != IpProtocol::Tcp || ip.frag_offset() != 0 || ip.more_frags() {
                    return None;
                }
                (
                    IpAddress::from(ip.src_addr()),
                    IpAddress::from(ip.dst_addr()),
                    &packet[usize::from(ip.header_len())..usize::from(ip.total_len())],
                    ip.verify_checksum(),
                )
            }
            6 => {
                let ip = Ipv6Packet::new_checked(packet).ok()?;
                if ip.next_header() != IpProtocol::Tcp {
                    return None;
                }
                (
                    IpAddress::from(ip.src_addr()),
                    IpAddress::from(ip.dst_addr()),
                    &packet[40..usize::from(ip.payload_len()).saturating_add(40)],
                    true,
                )
            }
            _ => return None,
        };
        let tcp = TcpPacket::new_checked(payload).ok()?;
        let opening = tcp.syn() && !tcp.ack() && !tcp.rst() && !tcp.fin();
        // Admission allocates a stack; reject corrupt SYNs before taking a permit.
        // Subsequent packets are checksum-validated by the established TCP stack.
        if opening && (!checksum_valid || !tcp.verify_checksum(&source, &destination)) {
            return None;
        }
        let key = FlowKey {
            source: SocketAddr::new(source.into(), tcp.src_port()),
            destination: SocketAddr::new(destination.into(), tcp.dst_port()),
        };
        if key.source.port() == 0
            || key.destination.port() == 0
            || !Self::unicast(key.source.ip())
            || !Self::unicast(key.destination.ip())
        {
            return None;
        }
        Some(Self { key, opening })
    }

    const fn unicast(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unspecified() && !ip.is_multicast(),
        }
    }
}

/// The stream and pending accept retain the stack and its admission permit.
struct FlowState {
    _net: Net,
    input: mpsc::Sender<io::Result<Vec<u8>>>,
    _permit: OwnedSemaphorePermit,
}

/// One established connection prepared for the broker's existing MITM boundary.
pub(super) struct AcceptedFlow {
    pub(super) key: FlowKey,
    pub(super) stream: tokio::io::DuplexStream,
}

/// Routes packets while weak entries leave stack lifetime to accepts and streams.
pub(super) struct TcpStack {
    flows: HashMap<FlowKey, Weak<FlowState>>,
    permits: Arc<Semaphore>,
    tasks: JoinSet<()>,
    accepted: mpsc::Sender<AcceptedFlow>,
    outgoing: mpsc::Sender<Vec<u8>>,
    mtu: usize,
}

impl TcpStack {
    pub(super) fn new(
        mtu: usize,
        outgoing: mpsc::Sender<Vec<u8>>,
        accepted: mpsc::Sender<AcceptedFlow>,
    ) -> Self {
        Self {
            flows: HashMap::new(),
            permits: Arc::new(Semaphore::new(SOCKET_LIMIT)),
            tasks: JoinSet::new(),
            accepted,
            outgoing,
            mtu,
        }
    }

    pub(super) fn has_tasks(&self) -> bool {
        !self.tasks.is_empty()
    }

    /// Reaps both expired accepts and completed forwarding tasks.
    pub(super) async fn reap(&mut self) -> io::Result<()> {
        self.tasks
            .join_next()
            .await
            .map_or(Ok(()), |task| task.map_err(io::Error::other))
    }

    pub(super) async fn receive(&mut self, packet: Vec<u8>) -> io::Result<()> {
        let Some(header) = PacketHeader::parse(&packet) else {
            return Ok(());
        };
        let state = match self.flows.get(&header.key).and_then(Weak::upgrade) {
            Some(state) => state,
            None if header.opening => {
                self.flows.retain(|_, state| state.strong_count() > 0);
                let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() else {
                    return Ok(());
                };
                self.admit(header.key, permit).await?
            }
            None => return Ok(()),
        };
        match state.input.try_send(Ok(packet)) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => {
                // Stalling here would also stall the shared output driver. Full
                // input queues discard packets; TCP owns congestion recovery.
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TUN TCP packet receiver closed",
            )),
        }
    }

    async fn admit(
        &mut self,
        key: FlowKey,
        permit: OwnedSemaphorePermit,
    ) -> io::Result<Arc<FlowState>> {
        let (input, incoming) = mpsc::channel(INPUT_QUEUE_LIMIT);
        let device = PacketDevice::new(incoming, self.outgoing.clone(), self.mtu);
        let mut interface = Config::new(HardwareAddress::Ip);
        interface.random_seed = rand::random();
        let address = IpAddress::from(key.destination.ip());
        let prefix = if key.destination.is_ipv4() { 32 } else { 128 };
        let mut config = NetConfig::new(interface, IpCidr::new(address, prefix), vec![address]);
        config.buffer_size.tcp_rx_size = STREAM_BUFFER_SIZE;
        config.buffer_size.tcp_tx_size = STREAM_BUFFER_SIZE;
        let net = Net::new(device, config);
        // Install the listener before the first SYN is queued for the reactor.
        let mut listener = net.tcp_bind(key.destination).await?;
        let state = Arc::new(FlowState {
            _net: net,
            input,
            _permit: permit,
        });
        self.flows.insert(key.clone(), Arc::downgrade(&state));
        let owner = Arc::clone(&state);
        let accepted = self.accepted.clone();
        self.tasks.spawn(async move {
            let stream = match tokio::time::timeout(ACCEPT_TIMEOUT, listener.accept()).await {
                Ok(Ok((stream, _))) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%error, "TUN TCP accept failed");
                    return;
                }
                Err(_) => return,
            };
            drop(listener);
            let mut stream = OwnedStream::new(stream, owner);
            let (client, mut bridge) = tokio::io::duplex(STREAM_BUFFER_SIZE);
            if accepted
                .send(AcceptedFlow {
                    key,
                    stream: client,
                })
                .await
                .is_err()
            {
                return;
            }
            // The broker may drop its IO after an HTTP exchange. The duplex EOF
            // makes Tokio drain writes and send TCP FIN before releasing Net.
            if let Err(error) = tokio::io::copy_bidirectional(&mut bridge, &mut stream).await {
                tracing::debug!(%error, "TUN TCP connection closed with IO error");
            }
        });
        Ok(state)
    }
}

#[cfg(test)]
mod tests;
