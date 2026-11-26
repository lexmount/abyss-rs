//! Resolve the owner of a local explicit-proxy TCP client from its kernel socket tuple.

use abyss_plugin_protocol::inspection::RequestSourceProcess;
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
use std::net::SocketAddr;
use tokio::sync::Semaphore;

// Socket-table enumeration is blocking. Bound concurrent queries for multiplexed clients.
static SCANS: Semaphore = Semaphore::const_new(2);

pub(super) async fn lookup(peer: Option<SocketAddr>, local: Option<SocketAddr>) -> Option<u32> {
    let (peer, local) = (peer?, local?);
    if !peer.ip().is_loopback() || !local.ip().is_loopback() {
        return None;
    }
    let permit = SCANS.acquire().await.ok()?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        socket_owner(peer, local)
    })
    .await
    .ok()
    .flatten()
}

fn socket_owner(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let family = if peer.is_ipv4() {
        AddressFamilyFlags::IPV4
    } else {
        AddressFamilyFlags::IPV6
    };
    let sockets = netstat2::get_sockets_info(family, ProtocolFlags::TCP).ok()?;
    let mut owners = sockets
        .into_iter()
        .filter_map(|socket| {
            let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info else {
                return None;
            };
            (tcp.state == netstat2::TcpState::Established
                && (tcp.local_addr, tcp.local_port) == (peer.ip(), peer.port())
                && (tcp.remote_addr, tcp.remote_port) == (local.ip(), local.port()))
                .then_some(socket.associated_pids)
        })
        .flatten();
    let owner = owners.next()?;
    (owner != 0 && owners.all(|pid| pid == owner)).then_some(owner)
}

pub(super) const fn source(pid: u32) -> RequestSourceProcess {
    RequestSourceProcess {
        pid: Some(pid),
        pid_version: None,
        name: None,
        executable_path: None,
        application_id: None,
        entry_point: None,
        working_directory: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn resolves_the_connected_client_and_ignores_remote_peers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = listener.local_addr().unwrap();
        let _client = tokio::net::TcpStream::connect(local).await.unwrap();
        let (_server, peer) = listener.accept().await.unwrap();
        assert_eq!(
            lookup(Some(peer), Some(local)).await,
            Some(std::process::id())
        );
        assert_eq!(
            lookup(Some("192.0.2.1:1234".parse().unwrap()), Some(local)).await,
            None
        );
    }
}
