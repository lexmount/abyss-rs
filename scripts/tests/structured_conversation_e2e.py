"""Replay captured HTTP fixtures through hook -> delivery -> isolated backend."""

import argparse
import hashlib
import json
import os
import secrets
import socket
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

ROLES = {"system", "developer", "user", "assistant", "reasoning", "tool", "unknown"}


def replay(binary, fixtures):
    completed = subprocess.run(
        [str(binary.resolve())],
        input="".join(json.dumps(v) + "\n" for v in fixtures),
        text=True,
        check=True,
        capture_output=True,
    )
    return [json.loads(line) for line in completed.stdout.splitlines()]


def messages(event):
    return [(m["role"], m["text"]) for m in event["conversation"]["messages"]]


def assert_structured(events):
    """Check the v2 conversation shape the hook emits before delivery."""
    assert len({event["event_id"] for event in events}) == len(events), events
    for event in events:
        assert "raw_body" not in event, event
        conversation = event["conversation"]
        assert "payloads" not in conversation, event
        for message in conversation["messages"]:
            assert set(message) == {"id", "role", "text"}, message
            assert message["role"] in ROLES, message
        assert conversation["completeness"] == "complete", event
        assert conversation["policy_omitted"] is False, event
    first_request, first_reply, second_request, second_reply = events[:4]
    assert first_request["conversation"]["thread_source"] == "user"
    assert first_request["conversation"]["instructions_present"] is True
    assert messages(first_request) == [
        ("developer", "system rules"),
        ("user", "continue"),
    ]
    # Repeated user prompts stay separate messages in request history.
    assert messages(second_request) == [
        ("developer", "system rules"),
        ("user", "continue"),
        ("assistant", "working"),
        ("user", "continue"),
    ]
    # Streamed deltas are assembled into one complete assistant message.
    for turn, reply in enumerate([first_reply, second_reply]):
        assert messages(reply) == [("assistant", "working")], reply
        assert reply["conversation"]["messages"][0]["id"] == f"m{turn}", reply
    anthropic_request, anthropic_reply = events[4:]
    assert messages(anthropic_request) == [
        ("system", "system rules"),
        ("user", "hello"),
    ]
    # Anthropic thinking is a separate reasoning message sharing the message id.
    assert messages(anthropic_reply) == [("reasoning", "plan"), ("assistant", "hi")]
    assert {m["id"] for m in anthropic_reply["conversation"]["messages"]} == {
        "anthropic-message"
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-binary", required=True, type=Path)
    parser.add_argument("--replay-binary", required=True, type=Path)
    parser.add_argument("--plugin-binary", required=True, type=Path)
    parser.add_argument("--artifacts", required=True, type=Path)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, exist_ok=True)
    for binary in [args.backend_binary, args.replay_binary, args.plugin_binary]:
        assert binary.is_file(), binary
    fixtures = []
    for turn in range(2):
        history = [{"role": "user", "content": "continue"}]
        if turn:
            history += [
                {"id": "m0", "role": "assistant", "content": "working"},
                {"role": "user", "content": "continue"},
            ]
        fixtures.append(
            {
                "path": "/v1/responses",
                "session_id": "structured-e2e-openai",
                "request": {
                    "model": "test-model",
                    "instructions": "system rules",
                    "input": history,
                    "client_metadata": {
                        "x-codex-turn-metadata": '{"thread_source":"user"}'
                    },
                },
                "response": "\n\n".join(
                    "data: " + json.dumps(v)
                    for v in [
                        {
                            "type": "response.output_text.delta",
                            "output_index": 0,
                            "content_index": 0,
                            "delta": "work",
                        },
                        {
                            "type": "response.output_text.delta",
                            "output_index": 0,
                            "content_index": 0,
                            "delta": "ing",
                        },
                        {
                            "type": "response.completed",
                            "response": {
                                "id": f"r{turn}",
                                "model": "test-model",
                                "output": [
                                    {
                                        "id": f"m{turn}",
                                        "role": "assistant",
                                        "content": [
                                            {"type": "output_text", "text": "working"}
                                        ],
                                    }
                                ],
                                "usage": {"input_tokens": 10, "output_tokens": 2},
                            },
                        },
                    ]
                )
                + "\n\n",
            }
        )
    fixtures.append(
        {
            "path": "/v1/messages",
            "session_id": "structured-e2e-anthropic",
            "request": {
                "model": "test-model",
                "system": "system rules",
                "messages": [{"role": "user", "content": "hello"}],
            },
            "response": {
                "id": "anthropic-message",
                "model": "test-model",
                "content": [
                    {"type": "thinking", "thinking": "plan", "signature": "sig"},
                    {"type": "text", "text": "hi"},
                ],
                "usage": {"input_tokens": 3, "output_tokens": 1},
            },
        }
    )
    events = replay(args.replay_binary, fixtures)
    assert len(events) == 6, events
    assert_structured(events)
    # Re-observing the same exchanges yields the same deterministic event ids.
    replayed = replay(args.replay_binary, fixtures)
    assert [e["event_id"] for e in replayed] == [e["event_id"] for e in events]
    assert [e["conversation"] for e in replayed] == [e["conversation"] for e in events]
    (args.artifacts / "agent-events.json").write_text(json.dumps(events, indent=2))
    with tempfile.TemporaryDirectory(prefix="abyss-v2-") as temporary:
        temp = Path(temporary)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        token = secrets.token_hex(24)
        base = f"http://127.0.0.1:{port}"
        env = dict(
            os.environ,
            ABYSS_BACKEND_ADDR=f"127.0.0.1:{port}",
            ABYSS_BACKEND_ENV="blackbox",
            ABYSS_BACKEND_API_TOKEN_SHA256=hashlib.sha256(token.encode()).hexdigest(),
            ABYSS_BACKEND_DATABASE_URL=str(temp / "events.sqlite"),
            ABYSS_BACKEND_RUN_MIGRATIONS="true",
        )
        backend_log = (args.artifacts / "backend.log").open("w")
        plugin_log = (args.artifacts / "delivery.log").open("w")
        backend = subprocess.Popen(
            [str(args.backend_binary.resolve())],
            env=env,
            stdout=backend_log,
            stderr=backend_log,
        )
        plugin = None

        def get(path):
            req = urllib.request.Request(
                base + path, headers={"Authorization": "Bearer " + token}
            )
            with urllib.request.urlopen(req, timeout=3) as response:
                return json.load(response)

        try:
            for _ in range(100):
                try:
                    get("/readyz")
                    break
                except (OSError, urllib.error.URLError):
                    assert backend.poll() is None, "backend exited"
                    time.sleep(0.1)
            else:
                raise AssertionError("backend did not start")
            auth = temp / "authorization"
            auth.write_text("Bearer " + token)
            socket_path = temp / "broker.sock"
            config = temp / "product.json"
            config.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "product": {"kind": "cli"},
                        "delivery_worker": {
                            "plugin_id": "structured-e2e",
                            "broker_endpoint": str(socket_path),
                            "delivery": {
                                "endpoint": base + "/v1/agent-usage/events",
                                "spool_enabled": False,
                            },
                            "authentication": {
                                "mode": "authorization_header_file",
                                "path": str(auth),
                            },
                        },
                    }
                )
            )
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(socket_path))
                listener.listen(1)
                listener.settimeout(10)
                plugin = subprocess.Popen(
                    [str(args.plugin_binary.resolve()), "--config", str(config)],
                    # Keep the plugin's runtime files out of the working tree.
                    env=dict(os.environ, ABYSS_HOME=str(temp / "abyss-home")),
                    stdout=plugin_log,
                    stderr=plugin_log,
                )
                stream, _ = listener.accept()
                with stream:
                    stream.settimeout(10)

                    def read_exact(count):
                        result = b""
                        while len(result) < count:
                            part = stream.recv(count - len(result))
                            assert part, "unexpected plugin disconnect"
                            result += part
                        return result

                    hello = json.loads(
                        read_exact(struct.unpack("!I", read_exact(4))[0])
                    )
                    assert hello["protocol_version"] == 2

                    def send(value):
                        data = json.dumps(value).encode()
                        stream.sendall(struct.pack("!I", len(data)) + data)

                    send({"protocol_version": 2})
                    for event in events:
                        send(event)
                    for _ in range(100):
                        stored = get("/v1/agent-usage/events?limit=100&fields=full")
                        if len(stored["events"]) == len(events):
                            break
                        time.sleep(0.1)
                    else:
                        raise AssertionError("delivery did not persist all events")
                    for session, expected in [
                        (
                            "structured-e2e-openai",
                            ["context", "user", "assistant", "user", "assistant"],
                        ),
                        # Reasoning and the reply are both assistant-side items.
                        (
                            "structured-e2e-anthropic",
                            ["context", "user", "assistant", "assistant"],
                        ),
                    ]:
                        selected = get(
                            "/v1/agent-usage/events?session_id=" + session + "&limit=10"
                        )
                        pk = selected["events"][0]["session_pk"]
                        trajectory = get(
                            "/v1/agent-usage/sessions/" + pk + "/trajectory"
                        )
                        assert [
                            item["kind"] for item in trajectory["items"]
                        ] == expected, trajectory
                        outline = get("/v1/agent-usage/sessions/" + pk + "/outline")
                        assert outline["session"]["title"] == (
                            "continue" if "openai" in session else "hello"
                        ), outline
                        (args.artifacts / (session + ".json")).write_text(
                            json.dumps(trajectory, indent=2)
                        )
                    # Check exact structured persistence without raw content.
                    import sqlite3

                    with sqlite3.connect(temp / "events.sqlite") as database:
                        rows = database.execute(
                            "SELECT event_id, metadata FROM llm_usage_events"
                        ).fetchall()
                    saved = {row[0]: json.loads(row[1]) for row in rows}
                    for event in events:
                        assert (
                            saved[event["event_id"]]["conversation"]
                            == event["conversation"]
                        )
                        assert "raw_body" not in saved[event["event_id"]]
                        assert (
                            "payloads" not in saved[event["event_id"]]["conversation"]
                        )
                    send({"code": 100, "reason": "test complete"})
            print(
                "PASS: hook -> v2 delivery -> SQLite storage -> titles and trajectory;"
                " role-aware messages, deterministic ids, no raw content"
            )
        finally:
            for child in [plugin, backend]:
                if child is not None and child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait()
            backend_log.close()
            plugin_log.close()


if __name__ == "__main__":
    main()
