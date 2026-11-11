"""Complete request context and decisions for broker plugin inspection."""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

from ..event import (
    Conversation,
    EventPurpose,
    ImageAttachment,
    _attachment,
    _conversation,
)


@dataclass(frozen=True)
class ModifyAction:
    """One explicit semantic operation; credential values are excluded from repr."""

    op: Literal["set_auth_token", "remove_auth_token", "set_model", "remove_model", "set_base_url"]
    value: Optional[str] = field(default=None, repr=False)

    @classmethod
    def set_auth_token(cls, token: str) -> "ModifyAction":
        return cls("set_auth_token", token)

    @classmethod
    def remove_auth_token(cls) -> "ModifyAction":
        return cls("remove_auth_token")

    @classmethod
    def set_model(cls, model: str) -> "ModifyAction":
        return cls("set_model", model)

    @classmethod
    def remove_model(cls) -> "ModifyAction":
        return cls("remove_model")

    @classmethod
    def set_base_url(cls, base_url: str) -> "ModifyAction":
        return cls("set_base_url", base_url)

    def to_dict(self) -> dict[str, Any]:
        if self.op in ("set_auth_token", "set_model", "set_base_url"):
            return {"op": self.op, "value": self.value}
        return {"op": self.op}


@dataclass(frozen=True)
class RequestDecision:
    """Explicit result; the SDK never compares or returns the callback context."""

    action: Literal["allow", "block", "modify"]
    reason: Optional[str] = None
    actions: tuple[ModifyAction, ...] = ()

    @classmethod
    def allow(cls) -> "RequestDecision":
        return cls("allow")

    @classmethod
    def block(cls, reason: str) -> "RequestDecision":
        return cls("block", reason=reason)

    @classmethod
    def modify(cls, actions: Iterable[ModifyAction]) -> "RequestDecision":
        return cls("modify", actions=tuple(actions))

    def to_dict(self) -> dict[str, Any]:
        if self.action == "modify":
            return {"action": self.action, "actions": [action.to_dict() for action in self.actions]}
        if self.action == "block":
            return {"action": self.action, "reason": self.reason}
        return {"action": self.action}


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
    auth_token: Optional[str] = field(repr=False)
    auth_token_writable: bool
    model_writable: bool
    base_url: Optional[str]
    base_url_writable: bool
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
