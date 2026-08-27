"""High-level broker plugin handshake and typed event stream."""

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ..event import AgentEvent
from .errors import AbyssPluginError, HandshakeRejectedError, UnexpectedBrokerEofError
from .framing import read_json_frame, write_json_frame
from .transport import PluginTransport, connect_plugin_transport, resolve_plugin_endpoint

PLUGIN_ID_PATTERN = re.compile(r"^[a-zA-Z0-9._-]{1,128}$")


@dataclass(frozen=True)
class BrokerClose:
    """Deliberate final frame sent by an accepted broker session."""

    code: int
    reason: str


class AgentEventStream(Iterator[AgentEvent]):
    """Synchronous typed Agent event iterator."""

    def __init__(self, transport: PluginTransport) -> None:
        self._transport = transport
        self.close: Optional[BrokerClose] = None
        self._finished = False

    def __iter__(self) -> "AgentEventStream":
        return self

    def __next__(self) -> AgentEvent:
        if self._finished:
            raise StopIteration
        try:
            frame = read_json_frame(self._transport)
            if frame is None:
                raise UnexpectedBrokerEofError
            close = _broker_close(frame)
            if close is not None:
                self.close = close
                self.close_stream()
                raise StopIteration
            if not isinstance(frame, Mapping):
                raise AbyssPluginError("broker Agent event frame must be an object")
            return AgentEvent.from_dict(frame)
        except StopIteration:
            raise
        except Exception:
            self.close_stream()
            raise

    def close_stream(self) -> None:
        """Close the local transport without waiting for another broker frame."""

        if not self._finished:
            self._finished = True
            self._transport.close()


class AbyssPlugin:
    """One configured out-of-process consumer of broker Agent events."""

    def __init__(self, plugin_id: str, endpoint: Optional[str] = None) -> None:
        if PLUGIN_ID_PATTERN.fullmatch(plugin_id) is None:
            raise ValueError(
                "plugin_id must contain 1-128 ASCII letters, digits, dots, underscores, or hyphens"
            )
        self._plugin_id = plugin_id
        self._endpoint = endpoint

    def connect(self) -> AgentEventStream:
        """Connect, perform the version 1 handshake, and return the event stream."""

        endpoint = resolve_plugin_endpoint(self._endpoint)
        transport = connect_plugin_transport(endpoint)
        try:
            write_json_frame(
                transport,
                {"protocol_version": 1, "plugin_id": self._plugin_id},
            )
            response = read_json_frame(transport)
            if response is None:
                raise UnexpectedBrokerEofError
            rejection = _broker_close(response)
            if rejection is not None:
                raise HandshakeRejectedError(rejection.code, rejection.reason)
            if not isinstance(response, Mapping) or response.get("protocol_version") != 1:
                raise AbyssPluginError("broker returned an invalid handshake response")
            return AgentEventStream(transport)
        except Exception:
            transport.close()
            raise

    def run(self, handler: Callable[[AgentEvent], None]) -> BrokerClose:
        """Handle events until the broker deliberately closes the stream."""

        stream = self.connect()
        try:
            for event in stream:
                handler(event)
            if stream.close is None:
                raise UnexpectedBrokerEofError
            return stream.close
        finally:
            stream.close_stream()


def _broker_close(value: Any) -> Optional[BrokerClose]:
    if not isinstance(value, Mapping):
        return None
    code = value.get("code")
    reason = value.get("reason")
    if isinstance(code, bool) or not isinstance(code, int) or not isinstance(reason, str):
        return None
    return BrokerClose(code=code, reason=reason)
