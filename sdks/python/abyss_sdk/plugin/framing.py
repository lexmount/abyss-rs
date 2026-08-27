"""Length-prefixed JSON codec for plugin protocol version 1."""

import json
import struct
from typing import Any, Optional

from .errors import AbyssPluginError
from .transport import PluginTransport

MAX_JSON_FRAME_BYTES = 16 * 1024 * 1024


def write_json_frame(stream: PluginTransport, value: object) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_JSON_FRAME_BYTES:
        raise AbyssPluginError(
            f"plugin frame payload length {len(payload)} exceeds maximum {MAX_JSON_FRAME_BYTES}"
        )
    stream.write_all(struct.pack(">I", len(payload)) + payload)


def read_json_frame(stream: PluginTransport) -> Optional[Any]:
    header = _read_exact(stream, 4, allow_initial_eof=True)
    if header is None:
        return None
    payload_length = struct.unpack(">I", header)[0]
    if payload_length > MAX_JSON_FRAME_BYTES:
        raise AbyssPluginError(
            f"plugin frame payload length {payload_length} exceeds maximum {MAX_JSON_FRAME_BYTES}"
        )
    payload = _read_exact(stream, payload_length, allow_initial_eof=False)
    assert payload is not None
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AbyssPluginError("decode broker plugin JSON frame") from error


def _read_exact(stream: PluginTransport, size: int, *, allow_initial_eof: bool) -> Optional[bytes]:
    chunks = bytearray()
    while len(chunks) < size:
        chunk = stream.read(size - len(chunks))
        if not chunk:
            if allow_initial_eof and not chunks:
                return None
            raise AbyssPluginError("broker plugin stream ended within a frame")
        chunks.extend(chunk)
    return bytes(chunks)
