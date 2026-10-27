//! Converts an Agent-owned proxy negotiation into the common MITM flow.
//!
//! Protocol relay lives in abyss-mitm; platform adapters supply an original-peer
//! connector. This layer coordinates them and rebinds logical target metadata.

use std::{net::SocketAddr, time::Duration};

use abyss_mitm::{
    DestinationAddress, FlowIngress, PrefixedDuplexStream, TransparentProxyContext,
    connect_relay::{ConnectProbe, ConnectRelayError, ConnectRelayOutcome, HttpConnectRelay},
};
use tokio::time::timeout;

use super::{IngressError, PlatformFlow};

const PREPARATION_TIMEOUT: Duration = Duration::from_secs(30);

impl PlatformFlow {
    /// Prepares only transparent CONNECT traffic. Existing explicit ingress has
    /// already selected its own route and must never be probed a second time.
    pub(crate) async fn prepare(mut self) -> Result<Option<Self>, IngressError> {
        let FlowIngress::Transparent {
            source,
            proxy: None,
        } = self.ingress
        else {
            return Ok(Some(self));
        };
        if self.prepared_upstream.is_some() {
            return Ok(Some(self));
        }
        let Some(connector) = self.original_proxy_connector.take() else {
            return Ok(Some(self));
        };
        let stream = PrefixedDuplexStream::new(self.read_prefix, self.io).boxed();
        let client = match ConnectProbe::read(stream, PREPARATION_TIMEOUT).await? {
            ConnectProbe::Other(stream) => {
                self.io = stream;
                self.read_prefix = Box::default();
                return Ok(Some(self));
            }
            ConnectProbe::Connect(stream) => stream,
        };
        let peer =
            self.metadata
                .original_destination
                .socket_addr()
                .ok_or(ConnectRelayError::Protocol(
                    "CONNECT requires a captured proxy peer",
                ))?;
        let upstream = timeout(PREPARATION_TIMEOUT, connector.connect(peer))
            .await
            .map_err(|_| ConnectRelayError::Timeout)?
            .map_err(|source| IngressError::OriginalProxy { peer, source })?;
        match HttpConnectRelay::default().relay(client, upstream).await? {
            ConnectRelayOutcome::Closed => Ok(None),
            ConnectRelayOutcome::Established {
                client,
                upstream,
                target,
            } => {
                self.metadata.original_destination = target
                    .host()
                    .as_ip_addr()
                    .map_or(DestinationAddress::Unknown, |address| {
                        DestinationAddress::Known(SocketAddr::new(address, target.port()))
                    });
                self.metadata.destination_host = target.host().as_dns_name().map(str::to_owned);
                self.ingress = FlowIngress::Transparent {
                    source,
                    proxy: Some(TransparentProxyContext {
                        target,
                        original_peer: peer,
                    }),
                };
                self.io = client;
                self.prepared_upstream = Some(upstream);
                self.read_prefix = Box::default();
                Ok(Some(self))
            }
        }
    }
}

#[cfg(test)]
mod tests;
