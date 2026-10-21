"""Independent native CLI observations and comparable, inclusive-input usage."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from scripts.agent_e2e_ci.model import ContractError


def counter(value: dict, key: str) -> int:
    count = value.get(key, 0)
    if type(count) is not int or count < 0:
        raise ContractError(f"invalid native usage counter: {key}")
    return count


@dataclass
class Transcript:
    final_text: str = ""
    session_id: str | None = None
    tool_outputs: list[str] = field(default_factory=list)
    call_ids: set[str] = field(default_factory=set)
    usage: list[dict[str, int]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    completed: bool = False

    @classmethod
    def parse(cls, harness: str, output: str) -> "Transcript":
        transcript = cls()
        current_usage = None
        for line in output.splitlines():
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ContractError("native client output is not JSONL") from error
            if not isinstance(event, dict):
                raise ContractError("native client JSONL event is not an object")
            kind = event.get("type")
            if harness == "codex":
                if kind == "thread.started":
                    transcript.session_id = event.get("thread_id")
                elif kind == "turn.completed":
                    transcript.completed = True
                    usage = event.get("usage", {})
                    transcript.usage.append(
                        {
                            k: counter(usage, k)
                            for k in (
                                "input_tokens",
                                "output_tokens",
                                "cached_input_tokens",
                                "cache_write_input_tokens",
                                "reasoning_output_tokens",
                            )
                            if k in usage
                        }
                    )
                elif kind in ("error", "turn.failed"):
                    transcript.errors.append(json.dumps(event))
                elif kind == "item.completed":
                    item = event.get("item", {})
                    if item.get("type") == "agent_message":
                        transcript.final_text += item.get("text", "")
                    elif item.get("type") in (
                        "command_execution",
                        "mcp_tool_call",
                        "tool_call",
                    ):
                        transcript.tool_outputs.append(json.dumps(item))
            elif harness == "claude-code":
                transcript.session_id = event.get("session_id", transcript.session_id)
                if kind == "result":
                    transcript.completed = not event.get("is_error", True)
                    transcript.final_text = event.get("result", "")
                    if not transcript.completed:
                        transcript.errors.append(json.dumps(event))
                if kind == "user":
                    for block in event.get("message", {}).get("content", []):
                        if (
                            isinstance(block, dict)
                            and block.get("type") == "tool_result"
                        ):
                            transcript.tool_outputs.append(
                                json.dumps(block.get("content"))
                            )
                            transcript.call_ids.add(block["tool_use_id"])
                # Assistant snapshots may contain provisional usage. The streaming
                # message_delta is authoritative and can lower earlier counters.
                if kind == "stream_event":
                    chunk = event.get("event", {})
                    if chunk.get("type") == "message_start":
                        current_usage = dict(chunk.get("message", {}).get("usage", {}))
                    elif (
                        chunk.get("type") == "message_delta"
                        and current_usage is not None
                    ):
                        current_usage.update(chunk.get("usage", {}))
                    elif (
                        chunk.get("type") == "message_stop"
                        and current_usage is not None
                    ):
                        transcript.usage.append(cls._messages_usage(current_usage))
                        current_usage = None
            else:
                if kind == "session":
                    transcript.session_id = event.get("sessionId")
                elif kind == "tool_result":
                    transcript.tool_outputs.append(json.dumps(event.get("result")))
                    transcript.call_ids.add(event["callId"])
                elif kind == "final":
                    transcript.completed = True
                    transcript.final_text = event.get("text", "")
                elif kind == "error":
                    transcript.errors.append(json.dumps(event))
                elif (
                    kind == "status"
                    and event.get("phase") == "step_end"
                    and "usage" in event
                ):
                    usage = event["usage"]
                    read, write = (
                        counter(usage, "cacheReadTokens"),
                        counter(usage, "cacheWriteTokens"),
                    )
                    result = {
                        "input_tokens": counter(usage, "inputTokens") + read + write,
                        "output_tokens": counter(usage, "outputTokens"),
                    }
                    for source, target in (
                        ("cacheReadTokens", "cached_input_tokens"),
                        ("cacheWriteTokens", "cache_write_input_tokens"),
                        ("reasoningTokens", "reasoning_output_tokens"),
                    ):
                        if source in usage:
                            result[target] = counter(usage, source)
                    transcript.usage.append(result)
        return transcript

    @staticmethod
    def _messages_usage(usage: dict) -> dict[str, int]:
        details = usage.get("input_tokens_details") or {}
        read = counter(usage, "cache_read_input_tokens")
        write = counter(usage, "cache_creation_input_tokens")
        result = {
            "input_tokens": counter(usage, "input_tokens") + read + write,
            "output_tokens": counter(usage, "output_tokens"),
        }
        for native, detail, target in (
            ("cache_read_input_tokens", "cached_tokens", "cached_input_tokens"),
            (
                "cache_creation_input_tokens",
                "cache_creation_tokens",
                "cache_write_input_tokens",
            ),
        ):
            if native in usage:
                result[target] = counter(usage, native)
            elif detail in details:
                result[target] = counter(details, detail)
        thinking = usage.get("output_tokens_details") or {}
        if "thinking_tokens" in thinking:
            result["reasoning_output_tokens"] = counter(thinking, "thinking_tokens")
        return result
