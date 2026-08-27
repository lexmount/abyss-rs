"""Unit and loopback black-box tests for Agent E2E process boundaries."""

from __future__ import annotations

import json
import socket
import socketserver
import subprocess
import sys
import threading
import unittest
from unittest.mock import Mock, patch

from scripts.agent_e2e_ci.process import (
    CommandRunner,
    LoopbackHttpClient,
    OrchestrationError,
    ProcessGroup,
)
from scripts.agent_e2e_ci.stack import _PortReservation


class _ResetThenReadyServer(socketserver.TCPServer):
    allow_reuse_address = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _ResetThenReadyHandler)
        self.request_count = 0


class _ResetThenReadyHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        server = self.server
        if not isinstance(server, _ResetThenReadyServer):
            raise TypeError("unexpected loopback test server")
        self.request.settimeout(1)
        request = bytearray()
        while b"\r\n\r\n" not in request:
            chunk = self.request.recv(4_096)
            if not chunk:
                break
            request.extend(chunk)
        server.request_count += 1
        if server.request_count == 1:
            self.request.shutdown(socket.SHUT_RDWR)
            return

        body = json.dumps({"status": "ok"}).encode("utf-8")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Connection: close\r\n\r\n"
            + body
        )
        self.request.sendall(response)


class LoopbackHttpClientTests(unittest.TestCase):
    def test_json_normalizes_connection_reset(self) -> None:
        client = LoopbackHttpClient()
        with (
            patch.object(
                client._opener,
                "open",
                side_effect=ConnectionResetError(104, "connection reset by peer"),
            ),
            self.assertRaisesRegex(OrchestrationError, "loopback JSON request failed") as raised,
        ):
            client.json("http://127.0.0.1:1/readyz")
        self.assertIsInstance(raised.exception.__cause__, ConnectionResetError)

    def test_attachment_normalizes_connection_reset(self) -> None:
        client = LoopbackHttpClient()
        with (
            patch.object(
                client._opener,
                "open",
                side_effect=ConnectionResetError(104, "connection reset by peer"),
            ),
            self.assertRaisesRegex(
                OrchestrationError,
                "loopback attachment request failed",
            ) as raised,
        ):
            client.bytes("http://127.0.0.1:1/media", bearer="unit-token")
        self.assertIsInstance(raised.exception.__cause__, ConnectionResetError)

    def test_readiness_recovers_after_real_connection_drop(self) -> None:
        server = _ResetThenReadyServer()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            port = int(server.server_address[1])
            client = LoopbackHttpClient()
            client.wait_until(
                lambda: client.json(
                    f"http://127.0.0.1:{port}/readyz",
                    timeout=1,
                ).get("status")
                == "ok",
                timeout_seconds=3,
                description="resetting loopback service",
            )
            self.assertEqual(server.request_count, 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class CommandRunnerTests(unittest.TestCase):
    def test_delivers_explicit_input_text_to_child_stdin(self) -> None:
        result = CommandRunner().run(
            [sys.executable, "-c", "import sys; print(sys.stdin.read())"],
            input_text="scenario prompt",
        )
        self.assertEqual(result.stdout, "scenario prompt\n")

    def test_forced_termination_remains_bounded_after_force_stop(self) -> None:
        process = Mock()
        process.pid = 42
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("child", 5),
            subprocess.TimeoutExpired(
                "child",
                5,
                output=b"partial stdout",
                stderr=b"partial stderr",
            ),
        ]
        with (
            patch.object(ProcessGroup, "request_stop") as request_stop,
            patch.object(ProcessGroup, "force_stop") as force_stop,
        ):
            stdout, stderr = CommandRunner._terminate_process_group(process)

        self.assertEqual(stdout, "partial stdout")
        self.assertEqual(stderr, "partial stderr")
        self.assertEqual(process.communicate.call_count, 2)
        request_stop.assert_called_once_with(process)
        force_stop.assert_called_once_with(process)


class ProcessGroupTests(unittest.TestCase):
    def test_popen_options_use_a_new_windows_process_group(self) -> None:
        with (
            patch("scripts.agent_e2e_ci.process.os.name", "nt"),
            patch.object(subprocess, "CREATE_NEW_PROCESS_GROUP", 512, create=True),
        ):
            self.assertEqual(ProcessGroup.popen_options(), {"creationflags": 512})

    def test_popen_options_use_a_new_posix_session(self) -> None:
        with patch("scripts.agent_e2e_ci.process.os.name", "posix"):
            self.assertEqual(ProcessGroup.popen_options(), {"start_new_session": True})

    def test_windows_force_stop_falls_back_when_taskkill_fails(self) -> None:
        process = Mock()
        process.pid = 42
        process.poll.return_value = None
        taskkill_result = Mock(returncode=1)
        with (
            patch("scripts.agent_e2e_ci.process.os.name", "nt"),
            patch("scripts.agent_e2e_ci.process.subprocess.run", return_value=taskkill_result),
        ):
            ProcessGroup.force_stop(process)

        process.kill.assert_called_once_with()


class PortReservationTests(unittest.TestCase):
    def test_holds_port_until_explicit_release(self) -> None:
        reservation = _PortReservation()
        competitor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            with self.assertRaises(OSError):
                competitor.bind(("127.0.0.1", reservation.port))
            reservation.release()
            competitor.bind(("127.0.0.1", reservation.port))
        finally:
            competitor.close()
            reservation.release()


if __name__ == "__main__":
    unittest.main()
