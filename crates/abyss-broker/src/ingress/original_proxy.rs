//! Platform capability for opening the Agent's original proxy connection.
//!
//! Implementations own socket creation and any OS-specific connection context.
//! The shared preparation layer owns timeouts, CONNECT negotiation and MITM.
//! An absent capability preserves the previous ingress path without probing IO.

use std::{future::Future, io, net::SocketAddr, pin::Pin};

use abyss_mitm::BoxedDuplexStream;

pub(super) type OriginalProxyConnect<'a> =
    Pin<Box<dyn Future<Output = io::Result<BoxedDuplexStream>> + Send + 'a>>;

/// Opens the captured peer without resolving or connecting to the inner target.
///
/// A future WFP adapter can retain per-flow redirect state here and apply it
/// before connecting. No platform context crosses into the protocol relay.
pub(super) trait OriginalProxyConnector: Send + Sync {
    fn connect(&self, peer: SocketAddr) -> OriginalProxyConnect<'_>;
}
