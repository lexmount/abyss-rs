//! Handshake and broker control wire payloads for plugin protocol version 1.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Broker plugin protocol versions supported by this SDK release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(try_from = "u16", into = "u16")]
pub enum PluginProtocolVersion {
    /// Initial handshake, live stream, and Agent event contract.
    V1,
}

impl PluginProtocolVersion {
    /// Returns the integer carried on the wire.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::V1 => 1,
        }
    }
}

impl From<PluginProtocolVersion> for u16 {
    fn from(version: PluginProtocolVersion) -> Self {
        version.wire_value()
    }
}

impl TryFrom<u16> for PluginProtocolVersion {
    type Error = UnsupportedPluginProtocolVersion;

    fn try_from(version: u16) -> Result<Self, Self::Error> {
        match version {
            1 => Ok(Self::V1),
            version => Err(UnsupportedPluginProtocolVersion { version }),
        }
    }
}

/// An unsupported broker plugin protocol version received from the wire.
#[derive(Debug, Error)]
#[error("unsupported broker plugin protocol version {version}")]
pub struct UnsupportedPluginProtocolVersion {
    version: u16,
}

impl UnsupportedPluginProtocolVersion {
    /// Returns the unsupported integer received from the peer.
    #[must_use]
    pub const fn version(&self) -> u16 {
        self.version
    }
}

/// Initial handshake sent from a plugin process to `abyss-broker`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginHello {
    /// Plugin protocol version requested by the plugin.
    pub protocol_version: PluginProtocolVersion,
    /// Stable identity used to describe this plugin connection.
    pub plugin_id: String,
}

impl PluginHello {
    /// Creates a version 1 plugin handshake.
    #[must_use]
    // Valid plugin identifiers are non-empty runtime strings, so exposing this
    // as const would suggest a construction mode that the wire contract rejects.
    #[expect(
        clippy::missing_const_for_fn,
        reason = "valid plugin identifiers are non-empty runtime strings"
    )]
    pub fn new(plugin_id: String) -> Self {
        Self {
            protocol_version: PluginProtocolVersion::V1,
            plugin_id,
        }
    }
}

/// Handshake response sent from `abyss-broker` to one plugin process.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerHello {
    /// Plugin protocol version confirmed by the broker.
    pub protocol_version: PluginProtocolVersion,
}

impl BrokerHello {
    /// Creates a version 1 broker handshake response.
    #[must_use]
    pub const fn v1() -> Self {
        Self {
            protocol_version: PluginProtocolVersion::V1,
        }
    }
}

/// Handshake rejection sent as the broker's first response frame.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerError {
    /// Stable rejection code interpreted in the handshake phase.
    pub code: u32,
    /// Human-readable rejection reason suitable for diagnostics.
    pub reason: String,
}

/// Deliberate final frame sent before the broker closes an accepted session.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerClose {
    /// Stable close code interpreted after a successful handshake.
    pub code: u32,
    /// Human-readable close reason suitable for diagnostics.
    pub reason: String,
}

/// Stable handshake rejection meanings defined by protocol version 1.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum BrokerErrorCode {
    /// The requested protocol version is not supported.
    UnsupportedProtocolVersion,
    /// The first frame is malformed or contains an invalid plugin identifier.
    InvalidHandshake,
    /// The broker cannot accept another plugin session.
    ResourceLimit,
}

impl BrokerErrorCode {
    /// Returns the integer carried in a `BrokerError` frame.
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::UnsupportedProtocolVersion => 1,
            Self::InvalidHandshake => 2,
            Self::ResourceLimit => 3,
        }
    }
}

/// Stable deliberate-close meanings defined by protocol version 1.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub enum BrokerCloseCode {
    /// The broker is shutting down normally.
    BrokerShutdown,
    /// The plugin fell behind the bounded live event stream.
    EventStreamTooSlow,
}

impl BrokerCloseCode {
    /// Returns the integer carried in a `BrokerClose` frame.
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        match self {
            Self::BrokerShutdown => 100,
            Self::EventStreamTooSlow => 101,
        }
    }
}

impl BrokerError {
    /// Creates a typed version 1 handshake rejection payload.
    #[must_use]
    pub fn new<T>(code: BrokerErrorCode, reason: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            code: code.wire_value(),
            reason: reason.into(),
        }
    }
}

impl BrokerClose {
    /// Creates a typed version 1 deliberate-close payload.
    #[must_use]
    pub fn new<T>(code: BrokerCloseCode, reason: T) -> Self
    where
        T: Into<String>,
    {
        Self {
            code: code.wire_value(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{BrokerClose, BrokerError, BrokerHello, PluginHello, PluginProtocolVersion};

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        let error = serde_json::from_value::<PluginProtocolVersion>(json!(7_u16))
            .expect_err("protocol version 7 must be rejected");

        assert!(
            error
                .to_string()
                .contains("unsupported broker plugin protocol version 7"),
            "error should identify the unsupported protocol version"
        );
    }

    #[test]
    fn constructors_emit_direct_v1_handshake_payloads() {
        let plugin_hello = serde_json::to_value(PluginHello::new("sample-plugin".to_owned()))
            .expect("plugin hello should serialize");
        let broker_hello =
            serde_json::to_value(BrokerHello::v1()).expect("broker hello should serialize");

        assert!(
            plugin_hello.get("type").is_none(),
            "session phase should identify PluginHello without a type discriminator"
        );
        assert!(
            broker_hello.get("type").is_none(),
            "session phase should identify BrokerHello without a type discriminator"
        );
        assert_eq!(
            plugin_hello["protocol_version"], 1_u16,
            "hello must request v1"
        );
        assert_eq!(
            plugin_hello["plugin_id"], "sample-plugin",
            "plugin id must be stable"
        );
        assert_eq!(
            broker_hello["protocol_version"], 1_u16,
            "broker hello must confirm plugin protocol v1"
        );
    }

    #[test]
    fn broker_control_payloads_serialize_without_wrapper_enums() {
        let broker_error = serde_json::to_value(BrokerError {
            code: 1,
            reason: "unsupported protocol version".to_owned(),
        })
        .expect("broker error should serialize");
        let broker_close = serde_json::to_value(BrokerClose {
            code: 101,
            reason: "plugin event stream is too slow".to_owned(),
        })
        .expect("broker close should serialize");

        assert!(broker_error.get("type").is_none());
        assert_eq!(broker_error["code"], 1_u32);
        assert_eq!(broker_error["reason"], "unsupported protocol version");
        assert!(broker_close.get("type").is_none());
        assert_eq!(broker_close["code"], 101_u32);
        assert_eq!(broker_close["reason"], "plugin event stream is too slow");
    }
}
