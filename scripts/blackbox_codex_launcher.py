"""Verify interactive Codex capture through the real CLI and a running stack.

Requires a configured CLI state root, a healthy broker, backend authorization,
and an installed, authenticated Codex. No Codex flags that implicitly disable
daemon reuse are supplied: the launcher must establish the process boundary.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import pty
import select
import signal
import struct
import termios
import time
import urllib.request
import uuid
from pathlib import Path


class InteractiveCodex:
    """Owns one terminal and terminates only the test's foreground process group."""

    def __init__(self, command: list[str], environment: dict[str, str]) -> None:
        self.command = command
        self.environment = environment

    def run(self, trace_path: Path, timeout: float) -> None:
        child_pid, terminal = pty.fork()
        if child_pid == 0:
            os.execvpe(self.command[0], self.command, self.environment)
        fcntl.ioctl(terminal, termios.TIOCSWINSZ, struct.pack("HHHH", 42, 150, 0, 0))
        output = bytearray()
        trusted = False
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                if not select.select([terminal], [], [], 0.2)[0]:
                    continue
                try:
                    chunk = os.read(terminal, 65536)
                except OSError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                self._answer_terminal_queries(terminal, chunk)
                if not trusted and b"Trust and continue" in output:
                    # The test creates this empty workspace itself.
                    os.write(terminal, b"\r")
                    trusted = True
                if b"state=done:app=codex" in output:
                    return
            raise RuntimeError(
                "Codex did not complete its interactive turn; inspect private trace"
            )
        finally:
            trace_path.write_bytes(output)
            trace_path.chmod(0o600)
            self._stop(child_pid)
            os.close(terminal)

    @staticmethod
    def _answer_terminal_queries(terminal: int, chunk: bytes) -> None:
        for query, response in (
            (b"\x1b[6n", b"\x1b[1;1R"),
            (b"\x1b[c", b"\x1b[?1;2c"),
            (b"\x1b]10;?", b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\"),
            (b"\x1b]11;?", b"\x1b]11;rgb:0000/0000/0000\x1b\\"),
        ):
            if query in chunk:
                os.write(terminal, response)

    @staticmethod
    def _stop(child_pid: int) -> None:
        try:
            os.killpg(child_pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if os.waitpid(child_pid, os.WNOHANG)[0]:
                return
            time.sleep(0.1)
        os.killpg(child_pid, signal.SIGKILL)
        os.waitpid(child_pid, 0)


class CaptureVerifier:
    """Checks persisted request/response content and usage for a unique marker."""

    def __init__(self, backend_url: str, bearer: str) -> None:
        self.backend_url = backend_url.rstrip("/")
        self.bearer = bearer
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def wait_for_events(self, marker: str) -> dict:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            request = urllib.request.Request(
                f"{self.backend_url}/v1/agent-usage/events?limit=200",
                headers={"Authorization": "Bearer " + self.bearer},
            )
            with self.http.open(request, timeout=15) as response:
                events = json.load(response)["events"]
            matches = [event for event in events if marker in json.dumps(event)]
            requests = [event for event in matches if event["event_type"] == "request"]
            responses = [
                event for event in matches if event["event_type"] == "response"
            ]
            if requests and responses:
                response = responses[-1]
                if response["agent"]["name"] != "codex":
                    raise RuntimeError("Persisted response was not identified as Codex")
                if response["token_usage"]["output_tokens"] <= 0:
                    raise RuntimeError(
                        "Persisted response has no output-token accounting"
                    )
                return {
                    "marker": marker,
                    "request_count": len(requests),
                    "response_count": len(responses),
                    "session_ids": sorted({event["session_id"] for event in matches}),
                    "event_ids": [event["event_id"] for event in matches],
                    "token_usage": response["token_usage"],
                    "model": response["llm"],
                }
            time.sleep(0.5)
        raise RuntimeError(
            "Interactive Codex completed without matching persisted request/response events"
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--abyss", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    parser.add_argument("--backend-url", required=True)
    parser.add_argument("--bearer-file", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    args = parser.parse_args()
    args.artifacts.mkdir(parents=True, mode=0o700, exist_ok=True)
    workspace = args.artifacts / "workspace"
    workspace.mkdir(mode=0o700, exist_ok=True)
    marker = "ABYSS_CODEX_LAUNCH_" + uuid.uuid4().hex
    command = [
        str(args.abyss.resolve()),
        "run",
        "--",
        "codex",
        "--no-alt-screen",
        "-C",
        str(workspace.resolve()),
        f"Reply exactly {marker} and do not use tools.",
    ]
    environment = os.environ.copy()
    environment.update(ABYSS_HOME=str(args.state_root.resolve()), TERM="xterm-256color")
    InteractiveCodex(command, environment).run(
        args.artifacts / "terminal.private.log", args.timeout
    )
    verifier = CaptureVerifier(args.backend_url, args.bearer_file.read_text().strip())
    result = verifier.wait_for_events(marker)
    result.update(command=command, result="pass")
    (args.artifacts / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
