//! Opens the original proxy peer for macOS Network Extension flows.
//!
//! The native adapter supplies the captured endpoint and excludes broker-owned
//! connections. This adapter opens TCP only; shared code handles CONNECT and TLS.

use std::net::SocketAddr;

use abyss_mitm::BoxedDuplexStream;
use tokio::net::TcpStream;

use super::super::original_proxy::{OriginalProxyConnect, OriginalProxyConnector};

pub(super) struct MacosOriginalProxyConnector;

impl OriginalProxyConnector for MacosOriginalProxyConnector {
    fn connect(&self, peer: SocketAddr) -> OriginalProxyConnect<'_> {
        Box::pin(async move {
            let stream: BoxedDuplexStream = Box::new(TcpStream::connect(peer).await?);
            Ok(stream)
        })
    }
}
