"""Typed plugin connection and protocol failures."""


class BrokerPluginError(RuntimeError):
    """Base plugin runtime failure."""


class HandshakeRejectedError(BrokerPluginError):
    """Broker rejected the initial plugin handshake."""

    def __init__(self, code: int, reason: str) -> None:
        super().__init__(f"broker rejected plugin handshake with code {code}: {reason}")
        self.code = code
        self.reason = reason


class UnexpectedBrokerEofError(BrokerPluginError):
    """Accepted broker stream ended without a deliberate close frame."""

    def __init__(self) -> None:
        super().__init__("broker plugin stream ended without BrokerClose")
