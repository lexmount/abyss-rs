//! Identifies outbound routes that would return to a broker-owned TCP listener.
//!
//! Wildcard listeners cover local interface addresses, not remote hosts sharing
//! the same port. Interface discovery stays here, outside platform ingress code.

use std::{
    io,
    net::{IpAddr, SocketAddr},
};

/// A bound listener used to reject direct and next-hop proxy loops.
pub struct ListenerEndpoint {
    address: SocketAddr,
}

impl ListenerEndpoint {
    /// Creates a guard for the actual bound address, including its assigned port.
    #[must_use]
    pub const fn new(address: SocketAddr) -> Self {
        Self { address }
    }

    /// Checks IP literals and localhost without resolving a proxy-owned target.
    ///
    /// # Errors
    /// Returns an error when local interface addresses cannot be enumerated.
    pub fn contains_target(&self, target: &crate::TargetAuthority) -> io::Result<bool> {
        match target.host() {
            crate::TargetHost::Ip(ip) => self.contains(SocketAddr::new(*ip, target.port())),
            crate::TargetHost::Dns(host) if host == "localhost" => Ok(self.contains(
                SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, target.port())),
            )? || self.contains(
                SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, target.port())),
            )?),
            crate::TargetHost::Dns(_) => Ok(false),
        }
    }

    /// Checks whether a destination belongs to this listener.
    ///
    /// Local interfaces are queried only for wildcard listeners and matching
    /// ports, so ordinary outbound traffic does not require interface discovery.
    ///
    /// # Errors
    /// Returns an error when local interface addresses cannot be enumerated.
    pub fn contains(&self, candidate: SocketAddr) -> io::Result<bool> {
        if candidate.port() != self.address.port() {
            return Ok(false);
        }
        let candidate = canonical_ip(candidate.ip());
        let listener = canonical_ip(self.address.ip());
        if candidate.is_unspecified() || candidate == listener {
            return Ok(true);
        }
        if !listener.is_unspecified() {
            return Ok(false);
        }
        // IPv6 wildcard listeners may also accept mapped IPv4 connections.
        if listener.is_ipv4() && candidate.is_ipv6() {
            return Ok(false);
        }
        if candidate.is_loopback() {
            return Ok(true);
        }
        Ok(if_addrs::get_if_addrs()?
            .iter()
            .any(|interface| canonical_ip(interface.ip()) == candidate))
    }
}

fn canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ipv6) => ipv6.to_ipv4_mapped().map_or(IpAddr::V6(ipv6), IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

#[cfg(test)]
mod tests {
    use super::ListenerEndpoint;

    #[test]
    fn recognizes_concrete_wildcard_and_mapped_addresses_without_blocking_remote_ports() {
        for (listener, candidate, expected) in [
            ("127.0.0.1:8080", "[::ffff:127.0.0.1]:8080", true),
            ("127.0.0.1:8080", "0.0.0.0:8080", true),
            ("0.0.0.0:8080", "127.0.0.1:8080", true),
            ("[::]:8080", "[::1]:8080", true),
            ("[::]:8080", "[::ffff:127.0.0.1]:8080", true),
            ("0.0.0.0:8080", "127.0.0.1:8081", false),
            ("0.0.0.0:8080", "192.0.2.1:8080", false),
            ("[::]:8080", "[2001:db8::1]:8080", false),
            ("192.0.2.1:8080", "192.0.2.2:8080", false),
        ] {
            assert_eq!(
                ListenerEndpoint::new(listener.parse().expect("listener"))
                    .contains(candidate.parse().expect("candidate"))
                    .expect("local interfaces"),
                expected,
                "{listener} -> {candidate}",
            );
        }
    }

    #[test]
    fn wildcard_covers_local_interfaces() {
        for interface in if_addrs::get_if_addrs().expect("local interfaces") {
            let ip = interface.ip();
            let listener = if ip.is_ipv4() {
                "0.0.0.0:8080"
            } else {
                "[::]:8080"
            };
            assert!(
                ListenerEndpoint::new(listener.parse().expect("listener"))
                    .contains(std::net::SocketAddr::new(ip, 8080))
                    .expect("local interfaces"),
                "{ip} must be covered by {listener}"
            );
        }
    }
}
