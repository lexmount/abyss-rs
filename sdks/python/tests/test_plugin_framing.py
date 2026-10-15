"""Plugin frame boundaries shared by every SDK."""

import socket
import struct
import unittest
from concurrent.futures import ThreadPoolExecutor

from abyss_sdk.plugin import BrokerPluginError
from abyss_sdk.plugin.framing import read_json_frame, write_json_frame
from abyss_sdk.plugin.transport import SocketTransport


class PluginFramingTests(unittest.TestCase):
    def test_v1_frame_above_former_limit(self) -> None:
        sender, receiver = socket.socketpair()
        with sender, receiver, ThreadPoolExecutor(max_workers=1) as executor:
            sender.settimeout(10)
            receiver.settimeout(10)
            text = "x" * (16 * 1024 * 1024 + 1)
            writing = executor.submit(write_json_frame, SocketTransport(sender), {"text": text})
            self.assertEqual(read_json_frame(SocketTransport(receiver)), {"text": text})
            writing.result(timeout=10)

    def test_rejects_above_64_mib_without_reading_body(self) -> None:
        sender, receiver = socket.socketpair()
        with sender, receiver:
            receiver.settimeout(2)
            sender.sendall(struct.pack(">I", 64 * 1024 * 1024 + 1))
            with self.assertRaisesRegex(BrokerPluginError, "exceeds maximum 67108864"):
                read_json_frame(SocketTransport(receiver))
