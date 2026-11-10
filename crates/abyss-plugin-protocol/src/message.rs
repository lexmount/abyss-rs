//! Version negotiation and broker control wire payloads.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Broker plugin protocol versions supported by this SDK release.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[non_exhaustive]
#[serde(try_from = "u16", into = "u16")]
pub enum PluginProtocolVersion {
    /// Handshake, live stream, and structured Agent event contract.
    V2,
}

impl PluginProtocolVersion {
    /// Returns the integer carried on the wire.
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::V2 => 2,
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
            2 => Ok(Self::V2),
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
    /// Capabilities enabled for this connection.
    pub capabilities: Vec<crate::inspection::PluginCapability>,
}

impl PluginHello {
    /// Creates a version 2 plugin handshake.
    #[must_use]
    pub fn new(plugin_id: String) -> Self {
        Self {
            protocol_version: PluginProtocolVersion::V2,
            plugin_id,
            capabilities: vec![crate::inspection::PluginCapability::AgentEvents],
        }
    }
}

/// Current plugin-to-broker messages on the shared connection.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum PluginMessage {
    /// Initial session handshake.
    PluginHello(PluginHello),
    /// Correlated request decision.
    InspectResponse(crate::inspection::InspectResponse),
}

/// Current broker-to-plugin messages on the shared connection.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[non_exhaustive]
pub enum BrokerMessage {
    /// Accepted session handshake.
    BrokerHello(BrokerHello),
    /// Rejected session handshake.
    BrokerError(BrokerError),
    /// Final session frame.
    BrokerClose(BrokerClose),
    /// Independent observation event.
    AgentEvent {
        /// Normalized event.
        event: std::sync::Arc<crate::event::AgentEvent>,
    },
    /// Full request awaiting a decision before forwarding.
    InspectRequest {
        /// Parsed and raw request context.
        context: std::sync::Arc<crate::inspection::AgentRequestContext>,
    },
}

/// Handshake response sent from `abyss-broker` to one plugin process.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerHello {
    /// Plugin protocol version confirmed by the broker.
    pub protocol_version: PluginProtocolVersion,
}

impl BrokerHello {
    /// Creates a version 2 broker handshake response.
    #[must_use]
    pub const fn v2() -> Self {
        Self {
            protocol_version: PluginProtocolVersion::V2,
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

/// Stable handshake rejection meanings defined by protocol version 2.
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

/// Stable deliberate-close meanings defined by protocol version 2.
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
    /// Creates a typed version 2 handshake rejection payload.
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
    /// Creates a typed version 2 deliberate-close payload.
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

    use super::{
        BrokerClose, BrokerError, BrokerHello, BrokerMessage, PluginHello, PluginMessage,
        PluginProtocolVersion,
    };

    #[test]
    fn unsupported_protocol_version_is_rejected() {
        let error = serde_json::from_value::<PluginProtocolVersion>(json!(1_u16))
            .expect_err("protocol version 1 must be rejected");

        assert!(
            error
                .to_string()
                .contains("unsupported broker plugin protocol version 1"),
            "error should identify the unsupported protocol version"
        );
    }

    #[test]
    fn handshake_frames_have_explicit_tags() {
        let plugin_hello = serde_json::to_value(PluginMessage::PluginHello(PluginHello::new(
            "sample-plugin".to_owned(),
        )))
        .expect("plugin hello should serialize");
        let broker_hello = serde_json::to_value(BrokerMessage::BrokerHello(BrokerHello::v2()))
            .expect("broker hello should serialize");

        assert_eq!(plugin_hello["type"], "plugin_hello");
        assert_eq!(broker_hello["type"], "broker_hello");
        assert_eq!(
            plugin_hello["capabilities"],
            serde_json::json!(["agent_events"])
        );
        assert_eq!(
            plugin_hello["protocol_version"], 2_u16,
            "hello must request v2"
        );
        assert_eq!(
            plugin_hello["plugin_id"], "sample-plugin",
            "plugin id must be stable"
        );
        assert_eq!(
            broker_hello["protocol_version"], 2_u16,
            "broker hello must confirm plugin protocol v2"
        );
    }

    #[test]
    fn broker_control_frames_have_explicit_tags() {
        let broker_error = serde_json::to_value(BrokerMessage::BrokerError(BrokerError {
            code: 1,
            reason: "unsupported protocol version".to_owned(),
        }))
        .expect("broker error should serialize");
        let broker_close = serde_json::to_value(BrokerMessage::BrokerClose(BrokerClose {
            code: 101,
            reason: "plugin event stream is too slow".to_owned(),
        }))
        .expect("broker close should serialize");

        assert_eq!(broker_error["type"], "broker_error");
        assert_eq!(broker_error["code"], 1_u32);
        assert_eq!(broker_error["reason"], "unsupported protocol version");
        assert_eq!(broker_close["type"], "broker_close");
        assert_eq!(broker_close["code"], 101_u32);
        assert_eq!(broker_close["reason"], "plugin event stream is too slow");
    }
}
