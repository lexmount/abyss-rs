//! Broker-local `WireGuard` material; serialized routes contain only its file path.

use std::{io::Read as _, net::IpAddr, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use serde::Deserialize;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::outbound::UpstreamProxyConfigError;

/// No Debug or Serialize: key material must stay out of logs and API replies.
#[derive(PartialEq)]
pub(super) struct Settings {
    pub(super) keys: Keys,
    pub(super) addresses: Box<[IpAddr]>,
    pub(super) allowed_ips: Box<[IpNet]>,
    pub(super) mtu: usize,
    pub(super) keepalive: Option<u16>,
}

#[derive(PartialEq, Zeroize, ZeroizeOnDrop)]
pub(super) struct Keys {
    pub(super) private: [u8; 32],
    pub(super) peer: [u8; 32],
    pub(super) preshared: Option<[u8; 32]>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSettings {
    private_key: Zeroizing<String>,
    public_key: String,
    #[serde(default)]
    preshared_key: Option<Zeroizing<String>>,
    addresses: Box<[IpAddr]>,
    allowed_ips: Box<[IpNet]>,
    #[serde(default = "default_mtu")]
    mtu: usize,
    #[serde(default)]
    persistent_keepalive_secs: Option<u16>,
}

impl Settings {
    pub(super) fn load(path: &Path) -> Result<Self, UpstreamProxyConfigError> {
        let file = std::fs::File::open(path)
            .map_err(|_| invalid("cannot read WireGuard configuration file"))?;
        let mut bytes = Zeroizing::new(Vec::new());
        file.take(0x0001_0001)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("cannot read WireGuard configuration file"))?;
        if bytes.len() > 0x0001_0000 {
            return Err(invalid("WireGuard configuration exceeds 64 KiB"));
        }
        // Never return serde's error: a malformed field can contain a secret.
        let file: FileSettings = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid WireGuard configuration JSON"))?;
        Self::parse(file)
    }

    fn parse(file: FileSettings) -> Result<Self, UpstreamProxyConfigError> {
        let keys = Keys {
            private: key(&file.private_key)?,
            peer: key(&file.public_key)?,
            preshared: file
                .preshared_key
                .as_ref()
                .map(|key_text| key(key_text))
                .transpose()?,
        };
        let private = StaticSecret::from(keys.private);
        if private
            .diffie_hellman(&PublicKey::from(keys.peer))
            .as_bytes()
            == &[0; 32]
        {
            return Err(invalid("WireGuard peer key must not have low order"));
        }
        if file.addresses.is_empty()
            || file.addresses.len() > 2
            || file.addresses.iter().any(|ip| !unicast(ip))
            || (file.addresses.len() == 2
                && file.addresses[0].is_ipv4() == file.addresses[1].is_ipv4())
        {
            return Err(invalid(
                "WireGuard requires at most one unicast address per IP family",
            ));
        }
        if file.allowed_ips.is_empty() || file.allowed_ips.len() > 256 {
            return Err(invalid("WireGuard requires 1..=256 allowed_ips networks"));
        }
        if !(1280..=1420).contains(&file.mtu) {
            return Err(invalid("WireGuard mtu must be in 1280..=1420"));
        }
        if file.persistent_keepalive_secs == Some(0) {
            return Err(invalid("WireGuard keepalive must be positive or omitted"));
        }
        Ok(Self {
            keys,
            addresses: file.addresses,
            allowed_ips: file.allowed_ips,
            mtu: file.mtu,
            keepalive: file.persistent_keepalive_secs,
        })
    }

    pub(super) fn allows(&self, ip: &IpAddr) -> bool {
        unicast(ip)
            && !self.addresses.contains(ip)
            && self
                .addresses
                .iter()
                .any(|local| local.is_ipv4() == ip.is_ipv4())
            && self.allowed_ips.iter().any(|network| network.contains(ip))
    }

    pub(super) fn identity(&self) -> ([u8; 32], [u8; 32]) {
        (
            PublicKey::from(&StaticSecret::from(self.keys.private)).to_bytes(),
            self.keys.peer,
        )
    }
}

fn key(value: &str) -> Result<[u8; 32], UpstreamProxyConfigError> {
    let mut bytes = Zeroizing::new([0; 32]);
    let length = STANDARD
        .decode_slice(value, bytes.as_mut())
        .map_err(|_| invalid("WireGuard keys must encode exactly 32 bytes in base64"))?;
    if length != 32 || *bytes == [0; 32] {
        return Err(invalid("WireGuard keys must encode 32 nonzero bytes"));
    }
    Ok(*bytes)
}

pub(super) const fn invalid(reason: &'static str) -> UpstreamProxyConfigError {
    UpstreamProxyConfigError(reason)
}

fn unicast(ip: &IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && *ip != IpAddr::V4(std::net::Ipv4Addr::BROADCAST)
        && !matches!(ip, IpAddr::V6(v6) if v6.to_ipv4_mapped().is_some() || v6.is_unicast_link_local())
        && !matches!(ip, IpAddr::V4(v4) if v4.is_link_local())
}

const fn default_mtu() -> usize {
    1280
}
