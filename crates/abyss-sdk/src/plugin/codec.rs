//! Length-prefixed JSON codec used by the public plugin client.

use std::io;

use abyss_plugin_protocol::MAX_JSON_FRAME_BYTES;
use serde::Serialize;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

const FRAME_HEADER_BYTES: usize = 4;

#[derive(Debug, Error)]
pub(super) enum PluginFrameError {
    #[error("plugin frame payload length {length} exceeds maximum {maximum}")]
    PayloadTooLarge { length: u32, maximum: u32 },
    #[error("unexpected EOF while reading plugin frame {part}")]
    UnexpectedEof { part: &'static str },
    #[error("{operation}: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("encode plugin JSON frame: {source}")]
    Json {
        #[source]
        source: serde_json::Error,
    },
}

pub(super) async fn read_payload<R>(reader: &mut R) -> Result<Option<Vec<u8>>, PluginFrameError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let Some(header) = read_header(reader).await? else {
        return Ok(None);
    };
    let payload_length = payload_length(header)?;
    let mut payload = vec![0_u8; payload_length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|source| map_read_error("payload", source))?;
    Ok(Some(payload))
}

pub(super) async fn write_json<W, T>(writer: &mut W, value: &T) -> Result<(), PluginFrameError>
where
    W: AsyncWrite + Send + Unpin + ?Sized,
    T: Serialize + Sync + ?Sized,
{
    let payload = serde_json::to_vec(value).map_err(|source| PluginFrameError::Json { source })?;
    let payload_length =
        u32::try_from(payload.len()).map_err(|_error| PluginFrameError::PayloadTooLarge {
            length: u32::MAX,
            maximum: MAX_JSON_FRAME_BYTES,
        })?;
    validate_payload_length(payload_length)?;
    writer
        .write_all(&header_bytes(payload_length))
        .await
        .map_err(|source| PluginFrameError::Io {
            operation: "write plugin frame header",
            source,
        })?;
    writer
        .write_all(&payload)
        .await
        .map_err(|source| PluginFrameError::Io {
            operation: "write plugin frame payload",
            source,
        })
}

async fn read_header<R>(
    reader: &mut R,
) -> Result<Option<[u8; FRAME_HEADER_BYTES]>, PluginFrameError>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut header = [0_u8; FRAME_HEADER_BYTES];
    let read = reader
        .read(&mut header[..1])
        .await
        .map_err(|source| PluginFrameError::Io {
            operation: "read plugin frame header",
            source,
        })?;
    if read == 0 {
        return Ok(None);
    }
    reader
        .read_exact(&mut header[1..])
        .await
        .map_err(|source| map_read_error("header", source))?;
    Ok(Some(header))
}

#[expect(
    clippy::big_endian_bytes,
    reason = "the published plugin protocol defines a big-endian u32 length"
)]
fn payload_length(header: [u8; FRAME_HEADER_BYTES]) -> Result<usize, PluginFrameError> {
    let payload_length = u32::from_be_bytes(header);
    validate_payload_length(payload_length)?;
    usize::try_from(payload_length).map_err(|_error| PluginFrameError::PayloadTooLarge {
        length: payload_length,
        maximum: MAX_JSON_FRAME_BYTES,
    })
}

#[expect(
    clippy::big_endian_bytes,
    reason = "the published plugin protocol defines a big-endian u32 length"
)]
const fn header_bytes(payload_length: u32) -> [u8; FRAME_HEADER_BYTES] {
    payload_length.to_be_bytes()
}

const fn validate_payload_length(payload_length: u32) -> Result<(), PluginFrameError> {
    if payload_length > MAX_JSON_FRAME_BYTES {
        return Err(PluginFrameError::PayloadTooLarge {
            length: payload_length,
            maximum: MAX_JSON_FRAME_BYTES,
        });
    }
    Ok(())
}

fn map_read_error(part: &'static str, source: io::Error) -> PluginFrameError {
    if source.kind() == io::ErrorKind::UnexpectedEof {
        return PluginFrameError::UnexpectedEof { part };
    }
    PluginFrameError::Io {
        operation: "read plugin frame",
        source,
    }
}
