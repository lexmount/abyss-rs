//! Framed wrapper-to-broker flow protocol.
//!
//! The macOS Network Extension sends one Unix socket connection per intercepted
//! flow. Each connection carries `ABY1` frames: one `FlowOpen`, zero or more
//! bidirectional `FlowData` frames, and directional `FlowClose` bookkeeping.
//! A close frame must name the byte direction that ended; the opposite
//! direction remains writable until it receives its own close.

use std::{io, net::IpAddr};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _};
#[cfg(test)]
use tokio::io::{AsyncWrite, AsyncWriteExt as _};
use uuid::Uuid;

const MAGIC: [u8; 4] = [0x41, 0x42, 0x59, 0x31];

/// Fixed frame header length.
pub const FRAME_HEADER_LEN: usize = 28;

/// Maximum accepted payload length for one frame.
pub const MAX_FRAME_PAYLOAD_LEN: u32 = 16 * 1024 * 1024;

/// Errors raised while parsing or writing framed flow protocol data.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FlowProtocolError {
    /// Frame magic did not match `ABY1`.
    #[error("invalid frame magic")]
    InvalidMagic,
    /// Frame type byte was not recognized.
    #[error("invalid frame type {0}")]
    InvalidFrameType(u8),
    /// Frame direction byte was not recognized.
    #[error("invalid frame direction {0}")]
    InvalidDirection(u8),
    /// Frame UUID bytes could not be decoded.
    #[error("invalid frame UUID: {source}")]
    InvalidUuid {
        /// Source UUID parsing error.
        #[source]
        source: uuid::Error,
    },
    /// Frame payload length exceeded the defensive cap.
    #[error("frame payload length {length} exceeds maximum {maximum}")]
    PayloadTooLarge {
        /// Payload length from the frame header.
        length: u32,
        /// Configured maximum payload length.
        maximum: u32,
    },
    /// The peer closed before a full frame was available.
    #[error("unexpected EOF while reading {operation}")]
    UnexpectedEof {
        /// Operation being performed.
        operation: &'static str,
    },
    /// A socket I/O operation failed.
    #[error("{operation}: {source}")]
    Io {
        /// Operation being performed.
        operation: &'static str,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// JSON frame payload could not be decoded or encoded.
    #[error("{operation}: {source}")]
    Json {
        /// Operation being performed.
        operation: &'static str,
        /// Source JSON error.
        #[source]
        source: serde_json::Error,
    },
}

/// Frame type byte.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowFrameType {
    /// Flow metadata frame.
    Open,
    /// Raw stream bytes.
    Data,
    /// End-of-flow bookkeeping.
    Close,
}

impl FlowFrameType {
    const fn wire_value(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Data => 2,
            Self::Close => 3,
        }
    }

    const fn from_wire(value: u8) -> Result<Self, FlowProtocolError> {
        match value {
            1 => Ok(Self::Open),
            2 => Ok(Self::Data),
            3 => Ok(Self::Close),
            value => Err(FlowProtocolError::InvalidFrameType(value)),
        }
    }
}

/// Data frame direction byte.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowFrameDirection {
    /// No byte direction, used for metadata frames.
    None,
    /// Bytes from the local client toward the broker.
    ClientToBroker,
    /// Bytes from the broker back to the local client.
    BrokerToClient,
}

impl FlowFrameDirection {
    const fn wire_value(self) -> u8 {
        match self {
            Self::None => 0,
            Self::ClientToBroker => 1,
            Self::BrokerToClient => 2,
        }
    }

    const fn from_wire(value: u8) -> Result<Self, FlowProtocolError> {
        match value {
            0 => Ok(Self::None),
            1 => Ok(Self::ClientToBroker),
            2 => Ok(Self::BrokerToClient),
            value => Err(FlowProtocolError::InvalidDirection(value)),
        }
    }
}

/// One decoded framed flow protocol frame.
#[derive(Debug)]
pub struct FlowFrame {
    frame_type: FlowFrameType,
    direction: FlowFrameDirection,
    flow_id: Uuid,
    payload: Vec<u8>,
}

impl FlowFrame {
    /// Creates a frame.
    #[must_use]
    pub const fn new(
        frame_type: FlowFrameType,
        direction: FlowFrameDirection,
        flow_id: Uuid,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            frame_type,
            direction,
            flow_id,
            payload,
        }
    }

    /// Creates a broker-to-client data frame.
    #[must_use]
    pub const fn broker_to_client(flow_id: Uuid, payload: Vec<u8>) -> Self {
        Self::new(
            FlowFrameType::Data,
            FlowFrameDirection::BrokerToClient,
            flow_id,
            payload,
        )
    }

    /// Creates an EOF frame for the broker-to-client byte direction.
    pub fn broker_to_client_eof(flow_id: Uuid, reason: &str) -> Result<Self, FlowProtocolError> {
        Self::close(flow_id, FlowFrameDirection::BrokerToClient, reason)
    }

    fn close(
        flow_id: Uuid,
        direction: FlowFrameDirection,
        reason: &str,
    ) -> Result<Self, FlowProtocolError> {
        let payload = serde_json::to_vec(&FlowClosePayload {
            flow_id,
            reason: reason.to_owned(),
        })
        .map_err(|source| FlowProtocolError::Json {
            operation: "encode FlowClose payload",
            source,
        })?;
        Ok(Self::new(FlowFrameType::Close, direction, flow_id, payload))
    }

    /// Returns the frame type.
    #[must_use]
    pub const fn frame_type(&self) -> FlowFrameType {
        self.frame_type
    }

    /// Returns the frame direction.
    #[must_use]
    pub const fn direction(&self) -> FlowFrameDirection {
        self.direction
    }

    /// Returns the flow identifier.
    #[must_use]
    pub const fn flow_id(&self) -> Uuid {
        self.flow_id
    }

    /// Returns the payload bytes.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Consumes the frame and returns the payload bytes.
    #[must_use]
    pub fn into_payload(self) -> Vec<u8> {
        self.payload
    }

    /// Encodes this frame as wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, FlowProtocolError> {
        let payload_length = u32::try_from(self.payload.len()).map_err(|_error| {
            FlowProtocolError::PayloadTooLarge {
                length: u32::MAX,
                maximum: MAX_FRAME_PAYLOAD_LEN,
            }
        })?;
        Self::validate_payload_len(payload_length)?;

        let capacity = FRAME_HEADER_LEN.checked_add(self.payload.len()).ok_or(
            FlowProtocolError::PayloadTooLarge {
                length: u32::MAX,
                maximum: MAX_FRAME_PAYLOAD_LEN,
            },
        )?;
        let mut encoded = Vec::with_capacity(capacity);
        encoded.extend_from_slice(&MAGIC);
        encoded.push(self.frame_type.wire_value());
        encoded.push(self.direction.wire_value());
        encoded.extend_from_slice(&[0, 0]);
        encoded.extend_from_slice(self.flow_id.as_bytes());
        encoded.extend_from_slice(&Self::payload_len_bytes(payload_length));
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    /// Decodes a complete frame from a header and payload.
    pub fn decode(
        header: &[u8; FRAME_HEADER_LEN],
        payload: Vec<u8>,
    ) -> Result<Self, FlowProtocolError> {
        let header = FlowFrameHeader::decode(header)?;
        Ok(Self::new(
            header.frame_type,
            header.direction,
            header.flow_id,
            payload,
        ))
    }

    /// Returns payload length from a decoded header.
    pub fn payload_len(header: &[u8; FRAME_HEADER_LEN]) -> Result<u32, FlowProtocolError> {
        Ok(FlowFrameHeader::decode(header)?.payload_len)
    }

    const fn validate_payload_len(length: u32) -> Result<(), FlowProtocolError> {
        if length > MAX_FRAME_PAYLOAD_LEN {
            return Err(FlowProtocolError::PayloadTooLarge {
                length,
                maximum: MAX_FRAME_PAYLOAD_LEN,
            });
        }
        Ok(())
    }
}

impl FlowFrame {
    #[expect(
        clippy::big_endian_bytes,
        reason = "The framed flow protocol defines payload length as big-endian wire bytes."
    )]
    const fn payload_len_bytes(payload_length: u32) -> [u8; 4] {
        payload_length.to_be_bytes()
    }
}

struct FlowFrameHeader {
    frame_type: FlowFrameType,
    direction: FlowFrameDirection,
    flow_id: Uuid,
    payload_len: u32,
}

impl FlowFrameHeader {
    fn decode(header: &[u8; FRAME_HEADER_LEN]) -> Result<Self, FlowProtocolError> {
        if header[0..4] != MAGIC {
            return Err(FlowProtocolError::InvalidMagic);
        }
        let payload_len = Self::payload_len_from_header(header);
        FlowFrame::validate_payload_len(payload_len)?;
        Ok(Self {
            frame_type: FlowFrameType::from_wire(header[4])?,
            direction: FlowFrameDirection::from_wire(header[5])?,
            flow_id: Self::flow_id_from_header(header)?,
            payload_len,
        })
    }

    fn flow_id_from_header(header: &[u8; FRAME_HEADER_LEN]) -> Result<Uuid, FlowProtocolError> {
        Uuid::from_slice(&header[8..24]).map_err(|source| FlowProtocolError::InvalidUuid { source })
    }

    #[expect(
        clippy::big_endian_bytes,
        reason = "The framed flow protocol defines payload length as big-endian wire bytes."
    )]
    const fn payload_len_from_header(header: &[u8; FRAME_HEADER_LEN]) -> u32 {
        u32::from_be_bytes([header[24], header[25], header[26], header[27]])
    }
}

/// Async frame codec for accepted flow sockets.
pub struct FlowFrameCodec;

impl FlowFrameCodec {
    /// Reads one complete frame. Returns `None` only when EOF occurs before a new
    /// frame starts.
    pub async fn read_frame<R>(reader: &mut R) -> Result<Option<FlowFrame>, FlowProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let Some(header) = Self::read_header(reader).await? else {
            return Ok(None);
        };
        let payload_len = usize::try_from(FlowFrame::payload_len(&header)?).map_err(|_error| {
            FlowProtocolError::PayloadTooLarge {
                length: u32::MAX,
                maximum: MAX_FRAME_PAYLOAD_LEN,
            }
        })?;
        let mut payload = vec![0; payload_len];
        reader
            .read_exact(&mut payload)
            .await
            .map_err(|source| Self::map_read_exact_error("read frame payload", source))?;
        Ok(Some(FlowFrame::decode(&header, payload)?))
    }

    /// Writes one complete frame.
    #[cfg(test)]
    pub async fn write_frame<W>(writer: &mut W, frame: &FlowFrame) -> Result<(), FlowProtocolError>
    where
        W: AsyncWrite + Unpin,
    {
        let encoded = frame.encode()?;
        writer
            .write_all(&encoded)
            .await
            .map_err(|source| FlowProtocolError::Io {
                operation: "write frame",
                source,
            })
    }

    async fn read_header<R>(
        reader: &mut R,
    ) -> Result<Option<[u8; FRAME_HEADER_LEN]>, FlowProtocolError>
    where
        R: AsyncRead + Unpin,
    {
        let mut header = [0; FRAME_HEADER_LEN];
        let read_len =
            reader
                .read(&mut header[..1])
                .await
                .map_err(|source| FlowProtocolError::Io {
                    operation: "read frame header",
                    source,
                })?;
        if read_len == 0 {
            return Ok(None);
        }
        reader
            .read_exact(&mut header[1..])
            .await
            .map_err(|source| Self::map_read_exact_error("read frame header", source))?;
        Ok(Some(header))
    }

    fn map_read_exact_error(operation: &'static str, source: io::Error) -> FlowProtocolError {
        if source.kind() == io::ErrorKind::UnexpectedEof {
            return FlowProtocolError::UnexpectedEof { operation };
        }
        FlowProtocolError::Io { operation, source }
    }
}

/// TCP-only protocol selector from `FlowOpen`.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FlowTransportProtocol {
    /// TCP flow bytes.
    Tcp,
}

/// JSON payload carried by a `FlowOpen` frame.
#[derive(Debug, Deserialize)]
pub struct FlowOpenPayload {
    /// Flow ID duplicated in JSON for protocol readability.
    #[serde(rename = "flow_id")]
    pub flow_id: Uuid,
    /// Source platform label from the wrapper.
    pub platform: String,
    /// Transport protocol.
    #[serde(rename = "protocol")]
    pub protocol_name: FlowTransportProtocol,
    /// Source process identifier.
    #[serde(rename = "source_pid")]
    pub source_pid: Option<u32>,
    /// Source process incarnation identifier from the macOS audit token.
    #[serde(rename = "source_pid_version")]
    pub source_pid_version: Option<u32>,
    /// Source executable path.
    #[serde(rename = "source_process")]
    pub source_process: Option<String>,
    /// Platform-normalized source application identity.
    #[serde(alias = "source_bundle_id")]
    pub source_application_id: Option<String>,
    /// Original destination host when available.
    #[serde(rename = "destination_host")]
    pub destination_host: Option<String>,
    /// Original destination IP when available.
    #[serde(rename = "destination_ip")]
    pub destination_ip: Option<IpAddr>,
    /// Original destination port.
    #[serde(rename = "destination_port")]
    pub destination_port: Option<u16>,
    /// Original TLS SNI when the wrapper already knows it.
    #[serde(rename = "original_tls_sni")]
    pub original_tls_sni: Option<String>,
}

impl FlowOpenPayload {
    /// Decodes a `FlowOpen` frame payload.
    pub fn decode(frame: &FlowFrame) -> Result<Self, FlowProtocolError> {
        serde_json::from_slice(frame.payload()).map_err(|source| FlowProtocolError::Json {
            operation: "decode FlowOpen payload",
            source,
        })
    }
}

/// JSON bookkeeping carried by a `FlowClose` frame.
#[derive(Deserialize, Serialize)]
pub(super) struct FlowClosePayload {
    /// Flow identifier duplicated from the frame header.
    #[serde(rename = "flow_id")]
    pub(super) flow_id: Uuid,
    /// Stable close reason supplied by the sending adapter.
    pub(super) reason: String,
}

impl FlowClosePayload {
    /// Decodes a `FlowClose` frame payload.
    pub(super) fn decode(frame: &FlowFrame) -> Result<Self, FlowProtocolError> {
        serde_json::from_slice(frame.payload()).map_err(|source| FlowProtocolError::Json {
            operation: "decode FlowClose payload",
            source,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{FlowFrame, FlowFrameDirection, FlowFrameType, FlowOpenPayload, FlowProtocolError};

    #[test]
    fn frame_round_trip_preserves_header_and_payload() {
        let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let frame = FlowFrame::new(
            FlowFrameType::Data,
            FlowFrameDirection::ClientToBroker,
            flow_id,
            b"hello".to_vec(),
        );

        let encoded = frame.encode().expect("frame should encode");
        let mut header = [0; super::FRAME_HEADER_LEN];
        header.copy_from_slice(&encoded[..super::FRAME_HEADER_LEN]);
        let decoded = FlowFrame::decode(&header, encoded[super::FRAME_HEADER_LEN..].to_vec())
            .expect("frame should decode");

        assert_eq!(decoded.frame_type(), FlowFrameType::Data);
        assert_eq!(decoded.direction(), FlowFrameDirection::ClientToBroker);
        assert_eq!(decoded.flow_id(), flow_id);
        assert_eq!(decoded.payload(), b"hello");
    }

    #[test]
    fn decode_rejects_invalid_magic() {
        let frame = FlowFrame::new(
            FlowFrameType::Data,
            FlowFrameDirection::ClientToBroker,
            uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef),
            Vec::new(),
        );
        let mut encoded = frame.encode().expect("frame should encode");
        encoded[0] = b'X';
        let mut header = [0; super::FRAME_HEADER_LEN];
        header.copy_from_slice(&encoded[..super::FRAME_HEADER_LEN]);

        let error = FlowFrame::decode(&header, Vec::new()).expect_err("magic should be rejected");

        assert!(matches!(error, FlowProtocolError::InvalidMagic));
    }

    #[test]
    fn flow_open_payload_uses_swift_json_field_names() {
        let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let payload = format!(
            r#"{{
                "flow_id": "{flow_id}",
                "platform": "macos",
                "protocol": "tcp",
                "source_pid": 123,
                "source_pid_version": 7,
                "source_process": "/usr/bin/curl",
                "source_application_id": "com.apple.curl",
                "destination_host": "api.example.test",
                "destination_ip": "127.0.0.1",
                "destination_port": 443,
                "original_tls_sni": null
            }}"#
        );
        let frame = FlowFrame::new(
            FlowFrameType::Open,
            FlowFrameDirection::None,
            flow_id,
            payload.into_bytes(),
        );

        let decoded = FlowOpenPayload::decode(&frame).expect("payload should decode");

        assert_eq!(decoded.flow_id, flow_id);
        assert_eq!(decoded.platform, "macos");
        assert_eq!(decoded.source_pid, Some(123));
        assert_eq!(decoded.source_pid_version, Some(7));
        assert_eq!(
            decoded.source_application_id.as_deref(),
            Some("com.apple.curl")
        );
        assert_eq!(decoded.destination_port, Some(443));
    }

    #[test]
    fn flow_open_payload_accepts_legacy_source_bundle_id() {
        let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let payload = format!(
            r#"{{
                "flow_id": "{flow_id}",
                "platform": "macos",
                "protocol": "tcp",
                "source_pid": null,
                "source_pid_version": null,
                "source_process": null,
                "source_bundle_id": "com.openai.codex",
                "destination_host": "api.openai.com",
                "destination_ip": "127.0.0.1",
                "destination_port": 443,
                "original_tls_sni": null
            }}"#
        );
        let frame = FlowFrame::new(
            FlowFrameType::Open,
            FlowFrameDirection::None,
            flow_id,
            payload.into_bytes(),
        );

        let decoded = FlowOpenPayload::decode(&frame).expect("legacy payload should decode");

        assert_eq!(
            decoded.source_application_id.as_deref(),
            Some("com.openai.codex")
        );
    }
}
