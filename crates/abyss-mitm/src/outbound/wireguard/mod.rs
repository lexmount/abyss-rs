//! `WireGuard` route snapshots, identity ownership and tunneled target connections.

mod config;
mod device;
#[cfg(test)]
mod tests;
mod tunnel;

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
    time::Duration,
};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use parking_lot::Mutex;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::lookup_host,
    time,
};

use super::{
    ConnectedTunnel, ProxyConnectStage, UpstreamProxyConfig, UpstreamProxyConfigError,
    UpstreamProxyError,
};
use crate::TargetAuthority;
use config::Settings;
use tunnel::Tunnel;

// The owning route manager shares this registry across configuration snapshots.
// Weak entries leave key, socket and task lifetimes to active routes and streams.
#[derive(Default)]
pub(super) struct RouteRegistry {
    identities: Mutex<Vec<Weak<WireguardRoute>>>,
}

pub(super) struct WireguardRoute {
    settings: Settings,
    endpoint: TargetAuthority,
    tunnel: tokio::sync::Mutex<Option<Arc<Tunnel>>>,
}

impl RouteRegistry {
    pub(super) fn load(
        &self,
        config: &UpstreamProxyConfig,
    ) -> Result<Arc<WireguardRoute>, UpstreamProxyConfigError> {
        let settings = Settings::load(
            config
                .wireguard_file
                .as_deref()
                .ok_or_else(|| config::invalid("wireguard_file is required"))?,
        )?;
        let endpoint = config.target()?;
        let identity = settings.identity();
        let mut identities = self.identities.lock();
        identities.retain(|entry| entry.strong_count() > 0);
        if let Some(entry) = identities
            .iter()
            .filter_map(Weak::upgrade)
            .find(|entry| entry.settings.identity() == identity)
        {
            if entry.settings == settings && entry.endpoint == endpoint {
                return Ok(entry);
            }
            return Err(config::invalid(
                "WireGuard identity is still in use with different settings; rotate the key or drain the old route first",
            ));
        }
        let route = Arc::new(WireguardRoute {
            settings,
            endpoint,
            tunnel: tokio::sync::Mutex::new(None),
        });
        identities.push(Arc::downgrade(&route));
        drop(identities);
        Ok(route)
    }
}

impl WireguardRoute {
    pub(super) async fn connect(
        self: &Arc<Self>,
        target: &TargetAuthority,
        peers: &[SocketAddr],
        handshake_timeout: Duration,
    ) -> Result<ConnectedTunnel, UpstreamProxyError> {
        let (tunnel, stream) = time::timeout(handshake_timeout, async {
            let tunnel = self.active_tunnel(peers).await?;
            let stream = self.connect_target(target, &tunnel).await?;
            Ok((tunnel, stream))
        })
        .await
        .map_err(|_| deadline(ProxyConnectStage::Handshake, handshake_timeout))?
        .map_err(|source| failed(ProxyConnectStage::Handshake, source))?;
        let proxy_peer = tunnel.peer;
        Ok(ConnectedTunnel {
            stream: Box::new(OwnedStream {
                stream,
                _route: Arc::clone(self),
                _tunnel: tunnel,
            }),
            proxy_peer,
        })
    }

    async fn active_tunnel(&self, peers: &[SocketAddr]) -> io::Result<Arc<Tunnel>> {
        let mut current = self.tunnel.lock().await;
        if let Some(tunnel) = current.as_ref().filter(|tunnel| tunnel.is_running()) {
            return Ok(Arc::clone(tunnel));
        }
        let peer = peers.first().copied().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "WireGuard peer resolved to no addresses",
            )
        })?;
        let tunnel = Tunnel::start(&self.settings, peer).await?;
        *current = Some(Arc::clone(&tunnel));
        drop(current);
        Ok(tunnel)
    }

    async fn connect_target(
        &self,
        target: &TargetAuthority,
        tunnel: &Tunnel,
    ) -> io::Result<tokio_smoltcp::TcpStream> {
        if let Some(ip) = target.host().as_ip_addr() {
            if !self.settings.allows(&ip) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "target is outside WireGuard allowed_ips or address families",
                ));
            }
            tunnel.connect(SocketAddr::new(ip, target.port())).await
        } else {
            let name = target.host().as_dns_name().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid target hostname")
            })?;
            let mut attempts = lookup_host((name, target.port()))
                .await?
                .filter(|address| self.settings.allows(&address.ip()))
                .map(|address| tunnel.connect(address))
                .collect::<FuturesUnordered<_>>();
            let mut last_error = io::Error::new(
                io::ErrorKind::NotFound,
                "target resolved to no addresses permitted by WireGuard settings",
            );
            while let Some(result) = attempts.next().await {
                match result {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = error,
                }
            }
            Err(last_error)
        }
    }
}

struct OwnedStream {
    stream: tokio_smoltcp::TcpStream,
    _route: Arc<WireguardRoute>,
    _tunnel: Arc<Tunnel>,
}

impl AsyncRead for OwnedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for OwnedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

const fn failed(stage: ProxyConnectStage, source: io::Error) -> UpstreamProxyError {
    UpstreamProxyError::Io { stage, source }
}

const fn deadline(stage: ProxyConnectStage, timeout: Duration) -> UpstreamProxyError {
    UpstreamProxyError::Timeout { stage, timeout }
}
