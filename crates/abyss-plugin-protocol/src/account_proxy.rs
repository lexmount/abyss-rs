//! Network proxy assigned to a provider credential. Secrets are excluded from diagnostics.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Transport to the account's next hop.
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AccountProxyProtocol {
    /// Plain HTTP CONNECT.
    Http,
    /// HTTP CONNECT inside verified TLS.
    Https,
    /// SOCKS5 with remote target DNS.
    Socks5,
}

/// Inline assignment delivered only in the private employee credential catalog.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountProxy {
    /// Proxy handshake and transport.
    pub protocol: AccountProxyProtocol,
    /// IP literal or DNS hostname without URL syntax.
    pub host: String,
    /// Explicit TCP port.
    pub port: u16,
    /// Optional proxy login. Supply both credential fields together.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Optional proxy password.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

impl AccountProxy {
    /// Checks a catalog assignment without resolving DNS or exposing supplied values.
    ///
    /// # Errors
    /// Rejects invalid addresses, incompatible authentication and incomplete credentials.
    pub fn validate(&self) -> Result<(), &'static str> {
        let dns = self.host.trim_end_matches('.').split('.').all(|label| {
            (1..=63).contains(&label.len())
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
        if self.port == 0
            || self.host.len() > 253
            || self.host.ends_with("..")
            || (self.host.parse::<IpAddr>().is_err() && !dns)
        {
            return Err("Invalid account proxy address.");
        }
        match (&self.username, &self.password) {
            (None, None) => Ok(()),
            (Some(user), Some(password))
                if !user.is_empty()
                    && !password.is_empty()
                    && !user.chars().chain(password.chars()).any(char::is_control)
                    && match self.protocol {
                        AccountProxyProtocol::Socks5 => user.len() <= 255 && password.len() <= 255,
                        _ => !user.contains(':') && user.len() <= 1024 && password.len() <= 1024,
                    } =>
            {
                Ok(())
            }
            _ => Err("Invalid account proxy credentials."),
        }
    }
}

impl AccountProxy {
    /// Formats a credential-free next-hop URL, including brackets for IPv6.
    #[must_use]
    pub fn endpoint(&self) -> String {
        let scheme = match self.protocol {
            AccountProxyProtocol::Http => "http",
            AccountProxyProtocol::Https => "https",
            AccountProxyProtocol::Socks5 => "socks5",
        };
        if self.host.contains(':') {
            format!("{scheme}://[{}]:{}", self.host, self.port)
        } else {
            format!("{scheme}://{}:{}", self.host, self.port)
        }
    }
}
