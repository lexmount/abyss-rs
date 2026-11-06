"""Complete request context and decisions for broker plugin inspection."""

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Callable, Literal, Optional

from ..event import (
    Conversation,
    EventPurpose,
    ImageAttachment,
    _attachment,
    _conversation,
)


@dataclass(frozen=True)
class RequestDecision:
    """A safe reason must never echo sensitive request content."""

    allow: bool
    reason: Optional[str] = None


@dataclass(frozen=True)
class RequestSourceProcess:
    """Available OS metadata; explicit proxy clients have no source process."""

    pid: Optional[int]
    pid_version: Optional[int]
    name: Optional[str]
    executable_path: Optional[str]
    application_id: Optional[str]
    entry_point: Optional[str]
    working_directory: Optional[str]


@dataclass(frozen=True)
class RequestHarness:
    """Harness identity and request-side declarations independent of audit policy."""

    id: str
    version: Optional[str]
    turn_id: Optional[str]
    subagent_id: Optional[str]
    parent_subagent_id: Optional[str]
    purpose: Optional[EventPurpose]


@dataclass(frozen=True)
class DecodedContent:
    """Lossless UTF-8 text or base64-encoded binary content."""

    encoding: Literal["utf8", "base64"]
    content: str


@dataclass(frozen=True)
class AgentRequestProjection:
    """Known request-side content, without invented response or usage fields."""

    protocol: str
    provider: str
    model: Optional[str]
    conversation: Conversation
    attachments: tuple[ImageAttachment, ...]
    tools: Any
    previous_response_id: Optional[str]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentRequestProjection":
        fields = dict(value)
        fields["conversation"] = _conversation(fields["conversation"])
        fields["attachments"] = tuple(_attachment(item) for item in fields["attachments"])
        return cls(**fields)


@dataclass(frozen=True)
class AgentRequestContext:
    """Full context before forwarding; credential headers are omitted."""

    flow_id: str
    request_id: str
    ingress: str
    source_process: Optional[RequestSourceProcess]
    destination: str
    destination_host: Optional[str]
    server_name: Optional[str]
    authority: Optional[str]
    proxy_endpoint: Optional[str]
    method: str
    path: str
    websocket: bool
    sequence: int
    message_type: Optional[Literal["text", "binary"]]
    headers: list[list[str]]
    body: DecodedContent
    json: Any
    parsing_status: Literal["parsed", "unknown_protocol", "invalid_payload"]
    harness: Optional[RequestHarness]
    agent: Optional[AgentRequestProjection]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentRequestContext":
        fields = dict(value)
        fields["body"] = DecodedContent(**fields["body"])
        if fields["source_process"] is not None:
            fields["source_process"] = RequestSourceProcess(**fields["source_process"])
        if fields["harness"] is not None:
            fields["harness"] = RequestHarness(**fields["harness"])
        if fields["agent"] is not None:
            fields["agent"] = AgentRequestProjection.from_dict(fields["agent"])
        return cls(**fields)


RequestHandler = Callable[[AgentRequestContext], RequestDecision]
