"""Public client factory tests over real local sockets and startup files."""

import json
import os
import socket
import struct
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from abyss_sdk import BrokerClient
from abyss_sdk.plugin import BrokerPlugin

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
)


class BrokerPluginClientTests(unittest.TestCase):
    def test_requires_usable_plugin_endpoint(self) -> None:
        for endpoint in (None, "", "  ", "bad\0socket"):
            with (
                self.subTest(endpoint=endpoint),
                self.assertRaisesRegex(ValueError, "plugin_endpoint"),
            ):
                BrokerClient("http://127.0.0.1:1", endpoint)
        client = BrokerClient("http://127.0.0.1:1", "/not/listening")
        for plugin_id in ("", "bad id", "x" * 129):
            with self.subTest(plugin_id=plugin_id), self.assertRaises(ValueError):
                client.plugin(plugin_id)

    def test_startup_info_requires_plugin_endpoint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "startup.json"
            token = Path(directory) / "token"
            token.write_text("local-token\n", encoding="utf-8")
            startup = {"api_addr": "127.0.0.1:1", "auth_token_file": str(token)}
            for endpoint in (None, "", " ", "bad\0socket"):
                path.write_text(
                    json.dumps({**startup, "plugin_endpoint": endpoint}), encoding="utf-8"
                )
                with self.subTest(endpoint=endpoint), self.assertRaises((TypeError, ValueError)):
                    BrokerClient.from_startup_info(str(path))
            path.write_text(json.dumps(startup), encoding="utf-8")
            with self.assertRaisesRegex(TypeError, "connection fields"):
                BrokerClient.from_startup_info(str(path))

    @unittest.skipIf(
        os.name == "nt", "Unix socket peer; real-broker tests cover platform transport"
    )
    def test_client_endpoints_and_plugin_lifecycles_are_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            first_endpoint = str(Path(directory) / "first.sock")
            second_endpoint = str(Path(directory) / "second.sock")
            first = BrokerClient("http://127.0.0.1:1", first_endpoint)
            plugin = first.plugin("first.consumer")
            self.assertIsInstance(plugin, BrokerPlugin)
            with (
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as first_listener,
                socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second_listener,
                ThreadPoolExecutor(max_workers=2) as workers,
            ):
                first_listener.bind(first_endpoint)
                second_listener.bind(second_endpoint)
                for listener in (first_listener, second_listener):
                    listener.listen()
                    listener.settimeout(5)
                first_peer = workers.submit(self.serve, first_listener, "first-event", 2)
                second_peer = workers.submit(self.serve, second_listener, "second-event", 1)
                token = Path(directory) / "token"
                token.write_text("local-token\n", encoding="utf-8")
                path = Path(directory) / "startup.json"
                startup = {
                    "api_addr": "127.0.0.1:1",
                    "auth_token_file": str(token),
                    "plugin_endpoint": second_endpoint,
                }
                path.write_text(json.dumps(startup), encoding="utf-8")
                second = BrokerClient.from_startup_info(str(path))
                path.write_text("{}", encoding="utf-8")
                second_plugin = second.plugin("second.consumer")
                del second
                received = []
                for consumer in (plugin, first.plugin("another.consumer"), second_plugin):
                    close = consumer.run(lambda event: received.append(event.event_id))
                    self.assertEqual(close.code, 100)
                self.assertEqual(received, ["first-event", "first-event", "second-event"])
                self.assertEqual(first_peer.result(), ["first.consumer", "another.consumer"])
                self.assertEqual(second_peer.result(), ["second.consumer"])

    def serve(self, listener: socket.socket, event_id: str, count: int) -> list[str]:
        identities = []
        for _ in range(count):
            stream, _ = listener.accept()
            with stream:
                stream.settimeout(5)
                size = struct.unpack("!I", self.read_exact(stream, 4))[0]
                hello = json.loads(self.read_exact(stream, size))
                self.assertEqual(hello["protocol_version"], 1)
                identities.append(hello["plugin_id"])
                event = json.loads(FIXTURE.read_text(encoding="utf-8"))
                event["event_id"] = event_id
                for frame in ({"protocol_version": 1}, event, {"code": 100, "reason": "complete"}):
                    payload = json.dumps(frame).encode()
                    stream.sendall(struct.pack("!I", len(payload)) + payload)
        return identities

    @staticmethod
    def read_exact(stream: socket.socket, count: int) -> bytes:
        data = b""
        while len(data) < count:
            chunk = stream.recv(count - len(data))
            if not chunk:
                raise EOFError("plugin closed before completing its handshake")
            data += chunk
        return data
