#!/usr/bin/env python3
"""Replay desktop conversation turns through the macOS ingress and broker event socket."""

import gzip
import json
import socketserver
import tempfile
from contextlib import contextmanager
from pathlib import Path

from blackbox_abyss_broker_transparent_upstream import framed_connection
from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    NextHop,
    read_all,
    read_head,
)
from blackbox_agent_parsing import Plugin
from blackbox_request_blocking import exact


def message(role, identifier, text):
    return {
        "id": identifier,
        "author": {"role": role},
        "recipient": "all",
        "content": {"content_type": "text", "parts": [text]},
    }


def example_turn(number):
    question = message("user", f"user-{number}", f"What is {number} + 1?")
    answer = message("assistant", f"assistant-{number}", "")
    session = "desktop-test"
    request = {"model": "auto", "messages": [question], "parent_message_id": "root"}
    if number == 2:
        request.update(conversation_id=session, parent_message_id="assistant-1")
    text = f"It is {number + 1}."
    frames = [
        {"type": "resume_conversation_token", "conversation_id": session},
        {
            "c": 1,
            "o": "add",
            "v": {
                "message": dict(
                    answer, metadata={"is_visually_hidden_from_conversation": True}
                )
            },
        },
        {"c": 2, "v": {"message": answer}},
        {"c": 1, "p": "/message/content/parts/0", "o": "append", "v": "hidden copy"},
        {"c": 2, "v": "It is "},
        {"v": text[6:]},
        {"type": "message_stream_complete"},
        "[DONE]",
    ]
    return request, [{"data": d} for d in frames], text, answer["id"]


def sse(frames):
    lines = []
    for frame in frames:
        lines.extend(f"{f['name']}: {f['value']}" for f in frame.get("fields", []))
        if "data" in frame:
            data = frame["data"]
            lines.append(
                "data: "
                + (
                    "[DONE]"
                    if data == "[DONE]"
                    else json.dumps(data, ensure_ascii=False)
                )
            )
        lines.append("")
    return ("\n".join(lines) + "\n").encode()


class Provider(socketserver.BaseRequestHandler):
    def handle(self):
        head = read_head(self.request)
        headers = {
            k.lower(): v.strip()
            for line in head.split(b"\r\n")[1:]
            if b":" in line
            for k, v in [line.split(b":", 1)]
        }
        request, frames, _, _ = self.server.turns.pop(0)
        assert (
            json.loads(exact(self.request, int(headers[b"content-length"]))) == request
        )
        body = gzip.compress(sse(frames))
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\n"
            + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
            + body
        )


@contextmanager
def environment(directory):
    origin, tls_origin, proxy = (
        LocalServer(Provider),
        LocalServer(Provider),
        LocalServer(NextHop),
    )
    proxy.origin, proxy.tls_origin = origin, tls_origin
    try:
        broker = Broker(directory, proxy, transparent=True)
        try:
            policy = broker.request("GET", "/v1/hooks/config")
            policy["harness_usage"]["enabled"] = True
            broker.request("PUT", "/v1/hooks/config", policy)
            yield broker, origin
        finally:
            broker.close()
    finally:
        for server in (proxy, tls_origin, origin):
            server.close()


def replay(directory, broker, origin, turns, inspected=False):
    endpoint = json.loads((directory / "startup.json").read_text())["plugin_endpoint"]
    plugin = Plugin(endpoint, inspected)
    origin.turns = list(turns)
    session = turns[1][0]["conversation_id"]
    try:
        for index, (request, _, answer, answer_id) in enumerate(turns):

            def send():
                wire = json.dumps(request).encode()
                with framed_connection(
                    broker,
                    "plain.invalid",
                    80,
                    application_id="com.openai.codex.helper",
                ) as connection:
                    connection.sendall(
                        b"POST /backend-api/f/conversation HTTP/1.1\r\nHost: chatgpt.com\r\n"
                        b"Originator: codex_chatgpt_desktop\r\nContent-Type: application/json\r\n"
                        + f"Content-Length: {len(wire)}\r\nConnection: close\r\n\r\n".encode()
                        + wire
                    )
                    assert read_all(connection).startswith(b"HTTP/1.1 200")

            events = plugin.observe(send, 2)
            assert [e["side"] for e in events] == ["request", "response"]
            user = request["messages"][-1]
            expected = [
                ("user", user["id"], "".join(user["content"]["parts"])),
                ("assistant", answer_id, answer),
            ]
            for event, (role, item_id, text) in zip(events, expected, strict=True):
                assert event["session_id"] == session
                assert event["agent"]["name"] == "chatgpt"
                assert event["response_id"] == answer_id
                assert event.get("previous_response_id") == (
                    turns[0][3] if index else None
                )
                assert event["conversation"]["completeness"] == "complete"
                assert event["conversation"]["entries"] == [
                    {"role": role, "item_id": item_id, "text": text}
                ]
            if inspected:
                assert (
                    plugin.contexts[-1]["agent"]["conversation"]["entries"]
                    == events[0]["conversation"]["entries"]
                )
    finally:
        plugin.close()


if __name__ == "__main__":
    turns = [example_turn(n) for n in (1, 2)]
    with tempfile.TemporaryDirectory(prefix="a-chat-", dir="/tmp") as name:
        directory = Path(name)
        with environment(directory) as (broker, origin):
            for inspection in (False, True):
                replay(directory, broker, origin, turns, inspection)
    print(
        "PASS: desktop helper, gzip SSE, two linked turns, exact visible entries, streaming/inspection parity"
    )
