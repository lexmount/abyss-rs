//! One encrypted peer and owned TCP/IP stacks; no operating-system route changes.

use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use boringtun::{
    noise::{Tunn, TunnResult},
    x25519::{PublicKey, StaticSecret},
};
use tokio::{net::UdpSocket, sync::mpsc, task::AbortHandle, time};
use tokio_smoltcp::{
    Net, NetConfig, TcpStream,
    smoltcp::{
        iface,
        wire::{HardwareAddress, IpCidr},
    },
};

use super::config::Settings;
use crate::netstack::PacketDevice;

/// The route and every target stream retain this owner; dropping it stops the driver.
pub(super) struct Tunnel {
    pub(super) peer: SocketAddr,
    stacks: Box<[(IpAddr, Net)]>,
    driver: AbortHandle,
}

impl Tunnel {
    pub(super) fn is_running(&self) -> bool {
        !self.driver.is_finished()
    }

    pub(super) async fn start(settings: &Settings, peer: SocketAddr) -> io::Result<Arc<Self>> {
        let local = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(local).await?;
        // A connected UDP socket accepts only this configured peer. Endpoint roaming
        // is intentionally not enabled for a fixed outbound route.
        socket.connect(peer).await?;
        let (outgoing, packets) = mpsc::channel(64);
        let (stacks, incoming): (Vec<_>, Vec<_>) = settings
            .addresses
            .iter()
            .map(|address| {
                let (sender, receiver) = mpsc::channel(64);
                let device = PacketDevice::new(receiver, outgoing.clone(), settings.mtu);
                let mut interface = iface::Config::new(HardwareAddress::Ip);
                let random = uuid::Uuid::new_v4();
                interface.random_seed =
                    u64::from_ne_bytes(random.as_bytes()[..8].try_into().expect("UUID prefix"));
                let prefix = if address.is_ipv4() { 32 } else { 128 };
                let config = NetConfig::new(
                    interface,
                    IpCidr::new((*address).into(), prefix),
                    vec![(*address).into()],
                );
                (
                    (*address, Net::new(device, config)),
                    StackInput {
                        address: *address,
                        sender,
                    },
                )
            })
            .unzip();
        drop(outgoing);
        let tunn = Tunn::new(
            StaticSecret::from(settings.keys.private),
            PublicKey::from(settings.keys.peer),
            settings.keys.preshared,
            settings.keepalive,
            1,
            None,
        );
        let driver = Driver {
            socket,
            tunn,
            packets,
            incoming: incoming.into_boxed_slice(),
            allowed_ips: settings.allowed_ips.clone(),
            peer,
        };
        let handle = tokio::spawn(driver.run());
        Ok(Arc::new(Self {
            peer,
            stacks: stacks.into_boxed_slice(),
            driver: handle.abort_handle(),
        }))
    }

    pub(super) async fn connect(&self, address: SocketAddr) -> io::Result<TcpStream> {
        let net = self
            .stacks
            .iter()
            .find(|(ip, _)| ip.is_ipv4() == address.is_ipv4())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no WireGuard address for target family",
                )
            })?;
        net.1.tcp_connect(address).await
    }
}

impl Drop for Tunnel {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

/// Routes decrypted packets to the stack owning their destination address.
struct StackInput {
    address: IpAddr,
    sender: mpsc::Sender<io::Result<Vec<u8>>>,
}

struct Driver {
    socket: UdpSocket,
    tunn: Tunn,
    packets: mpsc::Receiver<Vec<u8>>,
    incoming: Box<[StackInput]>,
    allowed_ips: Box<[ipnet::IpNet]>,
    peer: SocketAddr,
}

impl Driver {
    async fn run(mut self) {
        if self.pump().await.is_err() {
            // Wake stack readers with a generic error, without logging decrypted
            // traffic or handshake/key material supplied by the peer.
            self.incoming.iter().for_each(|input| {
                let _result = input.sender.try_send(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "WireGuard UDP transport failed",
                )));
            });
        }
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "Tokio's randomized select uses modulo internally for fair scheduling."
    )]
    async fn pump(&mut self) -> io::Result<()> {
        let mut receive = vec![0; 0x0001_0000].into_boxed_slice();
        let mut output = vec![0; 0x0001_0000].into_boxed_slice();
        let mut timers = time::interval(Duration::from_millis(250));
        timers.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                packet = self.packets.recv() => {
                    let Some(packet) = packet else { return Ok(()); };
                    let result = self.tunn.encapsulate(&packet, &mut output);
                    Self::dispatch(&self.socket, &self.incoming, &self.allowed_ips, result).await?;
                }
                received = self.socket.recv(&mut receive) => {
                    let length = received?;
                    let mut result = self.tunn.decapsulate(Some(self.peer.ip()), &receive[..length], &mut output);
                    // Only a network result requests draining queued datagrams.
                    // Follow that variant directly instead of mirroring it in a flag.
                    while let TunnResult::WriteToNetwork(packet) = result {
                        self.socket.send(packet).await?;
                        result = self.tunn.decapsulate(None, &[], &mut output);
                    }
                    Self::dispatch(&self.socket, &self.incoming, &self.allowed_ips, result).await?;
                }
                _ = timers.tick() => {
                    let result = self.tunn.update_timers(&mut output);
                    Self::dispatch(&self.socket, &self.incoming, &self.allowed_ips, result).await?;
                }
            }
        }
    }

    async fn dispatch(
        socket: &UdpSocket,
        incoming: &[StackInput],
        allowed_ips: &[ipnet::IpNet],
        result: TunnResult<'_>,
    ) -> io::Result<()> {
        let (packet, source) = match result {
            TunnResult::WriteToNetwork(packet) => {
                socket.send(packet).await?;
                return Ok(());
            }
            TunnResult::WriteToTunnelV4(packet, ip) => (packet, IpAddr::V4(ip)),
            TunnResult::WriteToTunnelV6(packet, ip) => (packet, IpAddr::V6(ip)),
            // Invalid unauthenticated datagrams are discarded; they must not kill
            // active streams. Retransmission and rekeying remain BoringTun-owned.
            TunnResult::Done | TunnResult::Err(_) => return Ok(()),
        };
        if !allowed_ips.iter().any(|network| network.contains(&source)) {
            return Ok(());
        }
        let Some(destination) = Tunn::dst_address(packet) else {
            return Ok(());
        };
        if let Some(input) = incoming.iter().find(|input| input.address == destination) {
            // UDP cannot exert end-to-end backpressure. Drop at the bounded queue
            // instead of stalling handshakes; the inner TCP connection retransmits.
            let _result = input.sender.try_send(Ok(packet.to_vec()));
        }
        Ok(())
    }
}
