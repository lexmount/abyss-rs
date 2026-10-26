//! Resolved destination metadata without forcing proxy targets through local DNS.
//!
//! The logical explicit-proxy authority remains in `FlowIngress`. An unknown
//! address means the next hop owns resolution, never that its peer is the target.

use std::{fmt, net::SocketAddr};

use super::OriginalDestination;

/// Whether the actual target socket address is known locally.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DestinationAddress {
    /// A captured or locally resolved target endpoint.
    Known(SocketAddr),
    /// A proxy owns target resolution and has not supplied the target address.
    Unknown,
}

impl DestinationAddress {
    /// Returns the target endpoint, never an upstream proxy's transport address.
    #[must_use]
    pub const fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::Known(address) => Some(*address),
            Self::Unknown => None,
        }
    }
}

impl From<OriginalDestination> for DestinationAddress {
    fn from(value: OriginalDestination) -> Self {
        Self::Known(value.socket_addr())
    }
}

impl fmt::Display for DestinationAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Known(address) => address.fmt(formatter),
            Self::Unknown => formatter.write_str("unresolved"),
        }
    }
}
