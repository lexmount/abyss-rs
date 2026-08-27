"""Typed Agent event contract carried by plugin protocol version 1."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional


@dataclass(frozen=True)
class DeviceContext:
    """Device context attached to an Agent event."""

    host_name: str
    platform: str
    os_version: Optional[str]


@dataclass(frozen=True)
class AgentContext:
    """Agent product context inferred from traffic."""

    name: str
    version: Optional[str]


@dataclass(frozen=True)
class LlmContext:
    """Provider and model context."""

    provider: str
    model: str


@dataclass(frozen=True)
class TokenUsage:
    """Normalized non-negative token counters."""

    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int
    total_tokens: int


@dataclass(frozen=True)
class ToolCall:
    """One normalized model-requested tool invocation."""

    call_id: str
    name: str
    input: str
    input_sha256: str


@dataclass(frozen=True)
class ToolResult:
    """One normalized tool result returned to the model."""

    call_id: str
    output: str
    output_sha256: str


@dataclass(frozen=True)
class ImageAttachment:
    """One policy-retained image attachment."""

    position: int
    media_type: str
    byte_size: int
    sha256: str
    content_base64: Optional[str]


@dataclass(frozen=True)
class AgentEvent:
    """One fully normalized broker Agent event."""

    event_id: str
    occurred_at: datetime
    device: DeviceContext
    agent: AgentContext
    session_id: str
    turn_index: int
    llm: LlmContext
    side: str
    text: Optional[str]
    token_usage: TokenUsage
    tool_calls: tuple[ToolCall, ...]
    tool_results: tuple[ToolResult, ...]
    attachments: tuple[ImageAttachment, ...]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentEvent":
        """Decode and validate one protocol version 1 event."""

        event = _mapping(value, "AgentEvent")
        _reject_unknown(
            event,
            {
                "event_id",
                "occurred_at",
                "device",
                "agent",
                "session_id",
                "turn_index",
                "llm",
                "side",
                "text",
                "token_usage",
                "tool_calls",
                "tool_results",
                "attachments",
            },
            "AgentEvent",
        )
        side = _string(event, "side")
        if side not in {"request", "response"}:
            raise ValueError("AgentEvent.side must be request or response")
        turn_index = _integer(event, "turn_index")
        if turn_index < 1:
            raise ValueError("AgentEvent.turn_index must be greater than zero")
        occurred_at = _datetime(_string(event, "occurred_at"))
        return cls(
            event_id=_string(event, "event_id"),
            occurred_at=occurred_at,
            device=_device(_mapping(event.get("device"), "AgentEvent.device")),
            agent=_agent(_mapping(event.get("agent"), "AgentEvent.agent")),
            session_id=_string(event, "session_id"),
            turn_index=turn_index,
            llm=_llm(_mapping(event.get("llm"), "AgentEvent.llm")),
            side=side,
            text=_optional_string(event, "text"),
            token_usage=_token_usage(_mapping(event.get("token_usage"), "AgentEvent.token_usage")),
            tool_calls=tuple(
                _tool_call(item)
                for item in _list(event.get("tool_calls", []), "AgentEvent.tool_calls")
            ),
            tool_results=tuple(
                _tool_result(item)
                for item in _list(event.get("tool_results", []), "AgentEvent.tool_results")
            ),
            attachments=tuple(
                _attachment(item)
                for item in _list(event.get("attachments", []), "AgentEvent.attachments")
            ),
        )


def _device(value: Mapping[str, Any]) -> DeviceContext:
    _reject_unknown(value, {"host_name", "platform", "os_version"}, "AgentEvent.device")
    return DeviceContext(
        host_name=_string(value, "host_name"),
        platform=_string(value, "platform"),
        os_version=_optional_string(value, "os_version"),
    )


def _agent(value: Mapping[str, Any]) -> AgentContext:
    _reject_unknown(value, {"name", "version"}, "AgentEvent.agent")
    return AgentContext(
        name=_string(value, "name"),
        version=_optional_string(value, "version"),
    )


def _llm(value: Mapping[str, Any]) -> LlmContext:
    _reject_unknown(value, {"provider", "model"}, "AgentEvent.llm")
    return LlmContext(provider=_string(value, "provider"), model=_string(value, "model"))


def _token_usage(value: Mapping[str, Any]) -> TokenUsage:
    fields = {
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_write_tokens",
        "reasoning_tokens",
        "total_tokens",
    }
    _reject_unknown(value, fields, "AgentEvent.token_usage")
    counters: dict[str, int] = {}
    for field in fields:
        counter = _integer(value, field)
        if counter < 0:
            raise ValueError(f"AgentEvent.token_usage.{field} must not be negative")
        counters[field] = counter
    return TokenUsage(**counters)


def _tool_call(value: Any) -> ToolCall:
    item = _mapping(value, "AgentEvent.tool_calls[]")
    _reject_unknown(item, {"call_id", "name", "input", "input_sha256"}, "tool call")
    return ToolCall(
        call_id=_string(item, "call_id"),
        name=_string(item, "name"),
        input=_string(item, "input"),
        input_sha256=_string(item, "input_sha256"),
    )


def _tool_result(value: Any) -> ToolResult:
    item = _mapping(value, "AgentEvent.tool_results[]")
    _reject_unknown(item, {"call_id", "output", "output_sha256"}, "tool result")
    return ToolResult(
        call_id=_string(item, "call_id"),
        output=_string(item, "output"),
        output_sha256=_string(item, "output_sha256"),
    )


def _attachment(value: Any) -> ImageAttachment:
    item = _mapping(value, "AgentEvent.attachments[]")
    _reject_unknown(
        item,
        {"position", "media_type", "byte_size", "sha256", "content_base64"},
        "attachment",
    )
    media_type = _string(item, "media_type")
    if media_type not in {"image/png", "image/jpeg", "image/webp", "image/gif"}:
        raise ValueError(f"unsupported AgentEvent attachment media type {media_type}")
    position = _integer(item, "position")
    byte_size = _integer(item, "byte_size")
    if position < 0 or byte_size < 0:
        raise ValueError("AgentEvent attachment sizes and positions must not be negative")
    return ImageAttachment(
        position=position,
        media_type=media_type,
        byte_size=byte_size,
        sha256=_string(item, "sha256"),
        content_base64=_optional_string(item, "content_base64"),
    )


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    return value


def _list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise TypeError(f"{label} must be an array")
    return value


def _string(value: Mapping[str, Any], field: str) -> str:
    result = value.get(field)
    if not isinstance(result, str):
        raise TypeError(f"{field} must be a string")
    return result


def _optional_string(value: Mapping[str, Any], field: str) -> Optional[str]:
    result = value.get(field)
    if result is None:
        return None
    if not isinstance(result, str):
        raise TypeError(f"{field} must be a string when present")
    return result


def _integer(value: Mapping[str, Any], field: str) -> int:
    result = value.get(field)
    if isinstance(result, bool) or not isinstance(result, int):
        raise TypeError(f"{field} must be an integer")
    return result


def _datetime(value: str) -> datetime:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("AgentEvent.occurred_at must be an RFC 3339 timestamp") from error


def _reject_unknown(value: Mapping[str, Any], allowed: set, label: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        raise ValueError(f"{label} contains unknown fields: {sorted(unknown)}")
