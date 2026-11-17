//! TCP socket admission and bounded asynchronous stream bridging for Linux TUN.
//!
//! Only this task touches smoltcp sockets. Duplex IO supplies backpressure at
//! the broker boundary; no provider, TLS, or capture policy belongs here.

use std::{collections::HashMap, io, net::SocketAddr};

use futures_util::FutureExt as _;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    socket::tcp,
    time::{Duration, Instant},
    wire::{HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv6Packet, TcpPacket},
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream};

use super::device::PacketDevice;

const SOCKET_LIMIT: usize = 256;
const STREAM_BUFFER_SIZE: usize = 0x0001_0000;

/// Original client and destination, including ports, identify one TCP socket.
#[derive(Debug, Hash, PartialEq, Eq)]
pub(super) struct FlowKey {
    pub(super) source: SocketAddr,
    pub(super) destination: SocketAddr,
}

impl FlowKey {
    /// Validates a complete unfragmented SYN before allocating a socket.
    pub(super) fn from_syn(packet: &[u8]) -> Option<Self> {
        let version = packet.first()?.checked_shr(4)?;
        let (source, destination, payload) = match version {
            4 => {
                let ip = Ipv4Packet::new_checked(packet).ok()?;
                if ip.next_header() != IpProtocol::Tcp
                    || ip.frag_offset() != 0
                    || ip.more_frags()
                    || !ip.verify_checksum()
                {
                    return None;
                }
                (
                    IpAddress::from(ip.src_addr()),
                    IpAddress::from(ip.dst_addr()),
                    &packet[usize::from(ip.header_len())..usize::from(ip.total_len())],
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
                )
            }
            _ => return None,
        };
        let tcp = TcpPacket::new_checked(payload).ok()?;
        if !tcp.syn()
            || tcp.ack()
            || tcp.rst()
            || tcp.fin()
            || !tcp.verify_checksum(&source, &destination)
        {
            return None;
        }
        Some(Self {
            source: SocketAddr::new(source.into(), tcp.src_port()),
            destination: SocketAddr::new(destination.into(), tcp.dst_port()),
        })
    }
}

struct FlowPipe {
    handle: SocketHandle,
    io: DuplexStream,
    client: Option<DuplexStream>,
    read_shutdown: bool,
    accept_deadline: Instant,
}

impl FlowPipe {
    fn new(handle: SocketHandle, now: Instant) -> Self {
        let (io, client) = tokio::io::duplex(STREAM_BUFFER_SIZE);
        Self {
            handle,
            io,
            client: Some(client),
            read_shutdown: false,
            accept_deadline: Instant::from_millis(now.total_millis().saturating_add(30_000)),
        }
    }

    /// Nonblocking reads/writes preserve the socket's own buffered bytes when
    /// the broker is backpressured. Both TCP half-closes remain independent.
    fn pump(&mut self, socket: &mut tcp::Socket<'_>) -> io::Result<()> {
        if socket.can_recv() {
            socket
                .recv(|bytes| match self.io.write(bytes).now_or_never() {
                    Some(Ok(size)) => (size, Ok(())),
                    Some(Err(error)) => (0, Err(error)),
                    None => (0, Ok(())),
                })
                .map_err(io::Error::other)??;
        }
        if !socket.may_recv()
            && !self.read_shutdown
            && let Some(result) = self.io.shutdown().now_or_never()
        {
            result?;
            self.read_shutdown = true;
        }
        if socket.can_send() {
            let received = socket
                .send(|bytes| {
                    self.io
                        .read(bytes)
                        .now_or_never()
                        .map_or((0, None), |result| {
                            (result.as_ref().copied().unwrap_or_default(), Some(result))
                        })
                })
                .map_err(io::Error::other)?;
            if let Some(result) = received
                && result? == 0
            {
                socket.close();
            }
        }
        Ok(())
    }
}

/// One userspace TCP stack with bounded pending and active socket admission.
pub(super) struct TcpStack {
    pub(super) device: PacketDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    flows: HashMap<FlowKey, FlowPipe>,
    now: Instant,
}

impl TcpStack {
    pub(super) fn new(mtu: usize) -> Self {
        let mut device = PacketDevice::new(mtu);
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = rand::random();
        let mut interface = Interface::new(config, &mut device, Instant::from_millis(0_i64));
        // These addresses exist only inside the userspace stack. Any-IP mode
        // accepts routed destinations while listening sockets retain their IP.
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::v4(0, 0, 0, 1), 0))
                .expect("IPv4 slot");
            addresses
                .push(IpCidr::new(IpAddress::v6(0, 0, 0, 0, 0, 0, 0, 1), 0))
                .expect("IPv6 slot");
        });
        interface.set_any_ip(true);
        Self {
            device,
            interface,
            sockets: SocketSet::new(Vec::new()),
            flows: HashMap::new(),
            now: Instant::from_millis(0_i64),
        }
    }

    pub(super) fn receive(&mut self, packet: Box<[u8]>) {
        if let Some(key) = FlowKey::from_syn(&packet)
            && !self.flows.contains_key(&key)
            && self.flows.len() < SOCKET_LIMIT
        {
            self.admit(key);
        }
        self.device.receive_packet(packet);
    }

    fn admit(&mut self, key: FlowKey) {
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; STREAM_BUFFER_SIZE]),
            tcp::SocketBuffer::new(vec![0; STREAM_BUFFER_SIZE]),
        );
        socket.set_timeout(Some(Duration::from_secs(30)));
        if socket.listen(key.destination).is_ok() {
            let handle = self.sockets.add(socket);
            self.flows.insert(key, FlowPipe::new(handle, self.now));
        }
    }

    /// Polls transport progress and hands established streams to the caller.
    /// Rejected handoffs abort their TCP socket without accumulating work.
    pub(super) fn poll<F>(&mut self, now: Instant, mut accepted: F)
    where
        F: FnMut(&FlowKey, DuplexStream) -> bool,
    {
        self.now = now;
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        self.flows.iter_mut().for_each(|(key, pipe)| {
            let socket = self.sockets.get_mut::<tcp::Socket<'_>>(pipe.handle);
            // Bound even sockets that never leave LISTEN after admission.
            if pipe.client.is_some() && now >= pipe.accept_deadline {
                socket.abort();
            }
            if socket.state() == tcp::State::Established
                && let Some(client) = pipe.client.take()
            {
                socket.set_timeout(Some(Duration::from_secs(7200)));
                socket.set_keep_alive(Some(Duration::from_secs(30)));
                if !accepted(key, client) {
                    socket.abort();
                }
            }
            if pipe.client.is_none() && pipe.pump(socket).is_err() {
                socket.abort();
            }
        });
        // Emit pending RSTs before removing aborted sockets.
        self.interface
            .poll(now, &mut self.device, &mut self.sockets);
        self.flows.retain(|_, pipe| {
            if self.sockets.get::<tcp::Socket<'_>>(pipe.handle).is_open() {
                true
            } else {
                self.sockets.remove(pipe.handle);
                false
            }
        });
    }
}

#[cfg(test)]
mod tests;
