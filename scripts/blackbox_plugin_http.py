#!/usr/bin/env python3
"""Exercise authenticated plugin upgrades against a real broker and provider."""
import json
import socket
import tempfile
import threading
import time
from pathlib import Path

from blackbox_abyss_broker_upstream import Broker, LocalServer, NextHop, read_head
from blackbox_request_blocking import Plugin, request, read_frame, write_frame
from blackbox_agent_parsing import Provider


def upgrade(broker, token, protocol="abyss-plugin-v1", expected=101):
    host, port = broker.api.rsplit(":", 1)
    stream = socket.create_connection((host, int(port)), timeout=5)
    stream.sendall((f"POST /v1/plugins/connect HTTP/1.1\r\nHost: {broker.api}\r\n"
                   f"Authorization: Bearer {token}\r\nConnection: keep-alive, Upgrade\r\n"
                   f"Upgrade: {protocol}\r\nContent-Length: 0\r\n\r\n").encode())
    head = read_head(stream)
    assert int(head.split(b" ", 2)[1]) == expected, head
    if expected != 101:
        stream.close()
        return None
    return stream


def main():
    origin, tls_origin, proxy = LocalServer(Provider), LocalServer(Provider), LocalServer(NextHop)
    origin.bodies, origin.messages = [], []
    origin.head_received, origin.release_reverse = threading.Event(), threading.Event()
    proxy.origin, proxy.tls_origin = origin, tls_origin
    broker = None
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-plugin-http-") as directory:
            directory = Path(directory)
            broker = Broker(directory, proxy)
            config = directory / "broker-config.toml"
            config.write_text('required_inspectors = ["enterprise"]\n' + config.read_text())
            broker.restart()
            hooks = broker.request("GET", "/v1/hooks/config")
            hooks["harness_usage"]["enabled"] = True
            broker.request("PUT", "/v1/hooks/config", hooks)
            startup = json.loads((directory / "startup.json").read_text())
            endpoint = Path(startup["plugin_endpoint"])
            assert endpoint.stat().st_mode & 0o777 == 0o600, "IPC ACL must remain owner-only"
            upgrade(broker, "invalid", expected=401)
            upgrade(broker, broker.token, protocol="wrong", expected=400)
            invalid = upgrade(broker, broker.token)
            write_frame(invalid, {"type": "plugin_hello", "protocol_version": 99,
                                  "plugin_id": "enterprise", "capabilities": ["agent_request"]})
            assert read_frame(invalid)["type"] == "broker_error"
            invalid.close()
            body = b'{"model":"test","input":"test"}'
            def denied():
                before = len(origin.bodies)
                assert b"503 Service Unavailable" in request(broker, body, headers=b"Session-Id: http-upgrade-test\r\n")
                assert len(origin.bodies) == before
            denied()
            plugin = Plugin(None, lambda _: True, ["agent_request", "agent_events"],
                            "enterprise", stream=upgrade(broker, broker.token))
            assert b"200 OK" in request(broker, body, headers=b"Session-Id: http-upgrade-test\r\n")
            for _ in range(50):
                if plugin.events:
                    break
                time.sleep(0.02)
            assert plugin.contexts and plugin.events, "inspection and observation must both survive upgrade"
            duplicate = Plugin(None, lambda _: True, plugin_id="enterprise", stream=upgrade(broker, broker.token))
            denied()
            duplicate.close()
            assert b"200 OK" in request(broker, body, headers=b"Session-Id: http-upgrade-test\r\n")
            plugin.close()
            denied()
            # Shutdown must include upgraded sessions in the normal lifecycle.
            observer = upgrade(broker, broker.token)
            write_frame(observer, {"type": "plugin_hello", "protocol_version": 1,
                                   "plugin_id": "observer", "capabilities": ["agent_events"]})
            assert read_frame(observer)["type"] == "broker_hello"
            broker.close()
            assert read_frame(observer)["type"] == "broker_close"
            observer.close()
        print("PASS: authenticated upgrade, unchanged IPC permissions, handshake rejection, inspection, observation, duplicate/lost inspector and shutdown")
    finally:
        if broker and not broker.log.closed:
            broker.close()
        for server in (proxy, origin, tls_origin):
            server.close()


if __name__ == "__main__":
    main()
