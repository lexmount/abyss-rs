//! Connection metadata shared by the broker proxy and platform adapters.

use std::{
    fmt,
    net::{IpAddr, SocketAddr},
};

use serde::Serialize;

/// Original remote endpoint captured before a platform redirect changed it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct OriginalDestination {
    pub ip: IpAddr,
    pub port: u16,
}

/// Special-purpose destination address ranges that deserve diagnostics.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DestinationAddressRange {
    /// `198.18.0.0/15` is reserved for benchmarking and is commonly used by
    /// local proxy fake-IP DNS implementations.
    Ipv4BenchmarkNet,
}

impl OriginalDestination {
    /// Converts the metadata to a standard socket address.
    #[must_use]
    pub const fn socket_addr(&self) -> SocketAddr {
        SocketAddr::new(self.ip, self.port)
    }

    /// Classifies destination IPs that are often synthetic proxy endpoints.
    #[must_use]
    pub const fn special_address_range(&self) -> Option<DestinationAddressRange> {
        match self.ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                if octets[0] == 198 && (octets[1] == 18 || octets[1] == 19) {
                    Some(DestinationAddressRange::Ipv4BenchmarkNet)
                } else {
                    None
                }
            }
            IpAddr::V6(_) => None,
        }
    }
}

impl DestinationAddressRange {
    /// Stable machine-readable classification name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ipv4BenchmarkNet => "fake_ip_candidate",
        }
    }

    /// CIDR range that triggered this classification.
    #[must_use]
    pub const fn cidr(self) -> &'static str {
        match self {
            Self::Ipv4BenchmarkNet => "198.18.0.0/15",
        }
    }

    /// Human-readable reason for support diagnostics.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Ipv4BenchmarkNet => {
                "destination_ip_in_ipv4_benchmark_net_commonly_used_for_proxy_fake_ip"
            }
        }
    }
}

impl fmt::Display for OriginalDestination {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.socket_addr().fmt(formatter)
    }
}

impl From<SocketAddr> for OriginalDestination {
    fn from(value: SocketAddr) -> Self {
        Self {
            ip: value.ip(),
            port: value.port(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use super::OriginalDestination;

    #[test]
    fn original_destination_formats_as_socket_addr() {
        let destination = OriginalDestination {
            ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            port: 80,
        };

        assert_eq!(destination.to_string(), "93.184.216.34:80");
        assert_eq!(
            destination.socket_addr(),
            SocketAddr::from(([93, 184, 216, 34], 80))
        );
    }

    #[test]
    fn original_destination_classifies_fake_ip_candidate_range() {
        let destination = OriginalDestination {
            ip: IpAddr::V4(Ipv4Addr::new(198, 19, 0, 2)),
            port: 443,
        };

        let range = destination
            .special_address_range()
            .expect("198.18.0.0/15 should be classified");
        assert_eq!(range.name(), "fake_ip_candidate");
        assert_eq!(range.cidr(), "198.18.0.0/15");
    }

    #[test]
    fn original_destination_does_not_classify_public_address() {
        let destination = OriginalDestination {
            ip: IpAddr::V4(Ipv4Addr::new(104, 18, 32, 47)),
            port: 443,
        };

        assert_eq!(destination.special_address_range(), None);
    }
}
