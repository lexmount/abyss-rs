#!/usr/bin/env python3
"""Check semantic actions against a real broker and local upstream sockets."""

import concurrent.futures
import gzip
import json
import socket
import struct
import tempfile
import threading
from pathlib import Path

from blackbox_request_blocking import (
    Broker,
    LocalServer,
    NextHop,
    Plugin,
    Provider,
    read_all,
    read_head,
    websocket_frame,
    websocket_read,
)


def modify(*actions):
    return {"action": "modify", "actions": list(actions)}


def send(broker, body, headers=b"", host="api.openai.com", chunked=False):
    with socket.create_connection(broker.address, timeout=12) as stream:
        framing = (
            b"Transfer-Encoding: chunked\r\n"
            if chunked
            else f"Content-Length: {len(body)}\r\n".encode()
        )
        stream.sendall(
            f"POST http://{host}:80/v1/responses HTTP/1.1\r\nHost: {host}\r\nOriginator: codex_cli_rs\r\n".encode()
            + headers
            + framing
            + b"\r\n"
            + body
        )
        return read_all(stream)


def checks(broker, origin, endpoint, proxy):
    original = b'{ "model": "before", "input": "hello", "extra": {"keep": [1, 2]} }'
    first = Plugin(
        endpoint,
        lambda context: modify(
            {"op": "set_auth_token", "value": "allocated-private-token"},
            {"op": "set_model", "value": "intermediate"},
        ),
    )

    def second_handler(context):
        assert context["auth_token"] == "allocated-private-token"
        assert context["agent"]["model"] == "intermediate"
        assert context["json"]["extra"] == {"keep": [1, 2]}
        assert context["auth_token_writable"] and context["model_writable"]
        assert all(name != "authorization" for name, _ in context["headers"])
        return modify({"op": "remove_model"}, {"op": "set_model", "value": "final"})

    second = Plugin(endpoint, second_handler)
    try:
        compressed = gzip.compress(original)
        chunks = (
            f"{len(compressed):x};tag=preserved\r\n".encode()
            + compressed
            + b"\r\n0\r\nX-End: yes\r\n\r\n"
        )
        assert send(
            broker,
            chunks,
            b"Content-Encoding: gzip\r\nTrailer: X-End\r\n",
            chunked=True,
        ).startswith(b"HTTP/1.1 200")
        head = origin.requests[-1].lower()
        assert b"authorization: bearer allocated-private-token\r\n" in head
        assert all(
            name not in head
            for name in [b"content-encoding:", b"transfer-encoding:", b"trailer:"]
        )
        assert json.loads(origin.bodies[-1]) == dict(
            json.loads(original), model="final"
        )
        assert f"content-length: {len(origin.bodies[-1])}\r\n".encode() in head
    finally:
        first.close()
        second.close()

    # Changing only the credential must preserve the wire body, including trailers.
    plugin = Plugin(
        endpoint,
        lambda _: modify({"op": "set_auth_token", "value": "auth-only-secret"}),
    )
    try:
        assert send(
            broker,
            chunks,
            b"Content-Encoding: gzip\r\nTrailer: X-End\r\n",
            chunked=True,
        ).startswith(b"HTTP/1.1 200")
        assert origin.bodies[-1] == chunks
        assert b"content-encoding: gzip" in origin.requests[-1].lower()
        assert b"trailer: x-end" in origin.requests[-1].lower()
    finally:
        plugin.close()

    plugin = Plugin(
        endpoint, lambda _: modify({"op": "remove_auth_token"}, {"op": "remove_model"})
    )
    try:
        assert send(
            broker, original, b"X-Api-Key: gateway-private\r\n", host="gateway.invalid"
        ).startswith(b"HTTP/1.1 200")
        assert b"x-api-key:" not in origin.requests[-1].lower()
        assert "model" not in json.loads(origin.bodies[-1])
        assert plugin.contexts[-1]["auth_token"] == "gateway-private"
    finally:
        plugin.close()

    # No action list may release partially edited data or call later plugins on failure.
    for decision, headers, host in [
        (
            modify(
                {"op": "set_model", "value": "must-not-leak"},
                {"op": "set_auth_token", "value": "private\r\ninjected"},
            ),
            b"",
            "api.openai.com",
        ),
        (
            modify({"op": "set_auth_token", "value": "unknown-target"}),
            b"",
            "gateway.invalid",
        ),
    ]:
        initial = len(origin.requests)
        plugin = Plugin(endpoint, lambda _, decision=decision: decision)
        later = Plugin(endpoint, lambda _: True)
        try:
            response = send(broker, original, headers, host)
            assert (
                response.startswith(b"HTTP/1.1 502")
                and b"invalid_agent_request_edit" in response
            )
            assert b"private" not in response
            assert len(origin.requests) == initial and not later.contexts
        finally:
            plugin.close()
            later.close()

    plugin = Plugin(endpoint, lambda _: modify({"op": "set_model", "value": "blocked"}))
    later = Plugin(endpoint, lambda _: False)
    try:
        initial = len(origin.requests)
        assert send(broker, original).startswith(b"HTTP/1.1 403")
        assert later.contexts[-1]["agent"]["model"] == "blocked"
        assert len(origin.requests) == initial
    finally:
        plugin.close()
        later.close()

    plugin = Plugin(endpoint, lambda _: modify())
    try:
        assert send(broker, original).startswith(b"HTTP/1.1 200")
        assert origin.bodies[-1] == original
    finally:
        plugin.close()

    for reject_auth, message_opcode in [(False, 1), (False, 2), (True, 1)]:
        pending, release = threading.Event(), threading.Event()
        origin.release_reverse.clear()

        def websocket_handler(context):
            if not context["websocket"]:
                assert context["auth_token_writable"] and not context["model_writable"]
                return modify({"op": "set_auth_token", "value": "ws-private-token"})
            assert (
                context["auth_token"] == "ws-private-token"
                and not context["auth_token_writable"]
            )
            assert context["model_writable"]
            pending.set()
            assert release.wait(3)
            return (
                modify({"op": "set_auth_token", "value": "forbidden"})
                if reject_auth
                else modify({"op": "set_model", "value": "ws-final"})
            )

        plugin = Plugin(endpoint, websocket_handler)
        try:
            with broker.connect("api.openai.com:80") as stream:
                stream.settimeout(4)
                stream.sendall(
                    b"GET /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
                )
                assert b"101" in read_head(stream)
                assert (
                    b"authorization: bearer ws-private-token"
                    in origin.requests[-1].lower()
                )
                document = {
                    "type": "response.create",
                    "response": {"model": "before", "input": []},
                    "extra": 42,
                }
                body = json.dumps(document).encode()
                stream.sendall(
                    websocket_frame(body[:30], opcode=message_opcode, final=False)
                    + websocket_frame(body[30:], opcode=0)
                )
                assert pending.wait(2)
                origin.release_reverse.set()
                assert websocket_read(stream) == (1, b"reverse"), (
                    "pending plugin blocked reverse traffic"
                )
                release.set()
                if reject_auth:
                    opcode, payload = websocket_read(stream)
                    assert opcode == 8 and struct.unpack(">H", payload[:2])[0] == 1011
                else:
                    # Provider records the reassembled message before closing the connection.
                    read_all(stream)
                    opcode, payload = origin.messages[-1]
                    document["response"]["model"] = "ws-final"
                    assert opcode == message_opcode and json.loads(payload) == document
        finally:
            release.set()
            plugin.close()

    check_observations(broker, proxy, endpoint)

    # Exercise the public Python API, including serialized action order and token repr.
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdks/python"))
    from abyss_sdk.plugin import BrokerPlugin, ModifyAction, RequestDecision

    def sdk_handler(context):
        assert "sdk-private" not in repr(context)
        return RequestDecision.modify(
            [
                ModifyAction.set_auth_token("python-private"),
                ModifyAction.set_model("python-model"),
            ]
        )

    stream = BrokerPlugin(
        "python-modifier", endpoint, on_agent_request=sdk_handler, agent_events=False
    ).connect()
    with concurrent.futures.ThreadPoolExecutor() as pool:
        task = pool.submit(next, stream, None)
        assert send(
            broker, original, b"Authorization: Bearer sdk-private\r\n"
        ).startswith(b"HTTP/1.1 200")
        assert json.loads(origin.bodies[-1])["model"] == "python-model"
        assert b"authorization: bearer python-private" in origin.requests[-1].lower()
        broker.close()
        task.result(timeout=5)


def check_observations(broker, proxy, endpoint):
    from blackbox_agent_parsing import (
        Plugin as Observer,
        Provider as EventProvider,
        websocket_turns,
    )
    from blackbox_request_blocking import request

    policy = broker.request("GET", "/v1/hooks/config")
    policy["harness_usage"]["enabled"] = True
    broker.request("PUT", "/v1/hooks/config", policy)
    observed_origin = LocalServer(EventProvider)
    observed_origin.bodies, observed_origin.messages = [], []
    # Events prefer a provider model when present; exercise the request fallback.
    observed_origin.response_model = None
    original_origin = proxy.origin
    proxy.origin = observed_origin
    observer = Observer(endpoint, False)
    modifier = Plugin(
        endpoint,
        lambda context: (
            modify({"op": "set_model", "value": "observed-final"})
            if context["model_writable"]
            else True
        ),
    )
    try:
        events = observer.observe(
            lambda: request(
                broker,
                b'{"model":"original","input":"hello"}',
                b"Session-Id: modified-observation\r\n",
            ),
            2,
        )
        assert (
            events[0]["side"] == "request"
            and events[0]["llm"]["model"] == "observed-final"
        )
        assert json.loads(observed_origin.bodies[-1])["model"] == "observed-final"
        assert "private" not in json.dumps(events)
        assert not observer.contexts, (
            "event-only subscribers received inspection context"
        )
        events = observer.observe(lambda: websocket_turns(broker), 4)
        assert all(
            event["llm"]["model"] == "observed-final"
            for event in events
            if event["side"] == "request"
        )
        assert all(
            message["model"] == "observed-final" for message in observed_origin.messages
        )
    finally:
        modifier.close()
        observer.close()
        proxy.origin = original_origin
        observed_origin.close()


def main():
    origin, tls_origin, proxy = (
        LocalServer(Provider),
        LocalServer(Provider),
        LocalServer(NextHop),
    )
    for server in (origin, tls_origin):
        server.bodies, server.messages = [], []
        server.head_received, server.release_reverse = (
            threading.Event(),
            threading.Event(),
        )
    proxy.origin, proxy.tls_origin = origin, tls_origin
    proxy.plain_hosts = ("api.openai.com", "gateway.invalid", "plain.invalid")
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-modify-") as temporary:
            directory = Path(temporary)
            try:
                broker = Broker(directory, proxy)
                endpoint = json.loads((directory / "startup.json").read_text())[
                    "plugin_endpoint"
                ]
                checks(broker, origin, endpoint, proxy)
                log = (directory / "broker.log").read_text()
                for secret in [
                    "allocated-private-token",
                    "auth-only-secret",
                    "gateway-private",
                    "ws-private-token",
                    "python-private",
                    "sdk-private",
                ]:
                    assert secret not in log
            except BaseException:
                print((directory / "broker.log").read_text()[-12000:])
                raise
            finally:
                if broker and not broker.log.closed:
                    broker.close()
        print(
            "PASS: ordered semantic actions, atomic failures, compressed/chunked writes, token-only byte retention, fixed WebSocket auth, model edits, reverse traffic, Python SDK and secret-free logs"
        )
    finally:
        proxy.close()
        origin.close()
        tls_origin.close()


if __name__ == "__main__":
    main()
