"""Subprocess and loopback HTTP boundaries for the CI orchestrator."""

from __future__ import annotations

import http.client
import json
import os
import signal
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


class OrchestrationError(RuntimeError):
    """Raised when a trusted CI infrastructure operation cannot complete."""


class ProcessGroup:
    """Creates and terminates isolated child process groups on every host OS."""

    @staticmethod
    def popen_options() -> dict[str, bool | int]:
        if os.name == "nt":
            return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
        return {"start_new_session": True}

    @staticmethod
    def request_stop(process: subprocess.Popen[Any]) -> None:
        if process.poll() is not None:
            return
        try:
            if os.name == "nt":
                process.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(process.pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            if os.name == "nt" and process.poll() is None:
                try:
                    process.terminate()
                except (OSError, ProcessLookupError):
                    pass

    @staticmethod
    def force_stop(process: subprocess.Popen[Any]) -> None:
        if process.poll() is not None:
            return
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            return

        try:
            result = subprocess.run(
                ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except OSError:
            result = None
        if result is None or (result.returncode != 0 and process.poll() is None):
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass


@dataclass(frozen=True)
class CommandResult:
    """Captured outcome of a child process, including bounded timeout state."""

    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool


class CommandRunner:
    """Runs commands without a shell and records exact process outcomes."""

    def run(
        self,
        args: list[str],
        *,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        timeout: int | None = None,
        check: bool = True,
        label: str | None = None,
    ) -> CommandResult:
        started = time.monotonic()
        process = subprocess.Popen(
            args,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            **ProcessGroup.popen_options(),
        )
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
            result = CommandResult(
                args=tuple(args),
                returncode=process.returncode,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=time.monotonic() - started,
                timed_out=False,
            )
        except subprocess.TimeoutExpired:
            stdout, stderr = self._terminate_process_group(process)
            result = CommandResult(
                args=tuple(args),
                returncode=124,
                stdout=stdout,
                stderr=stderr,
                duration_seconds=time.monotonic() - started,
                timed_out=True,
            )
        except BaseException:
            self._terminate_process_group(process)
            raise
        if check and result.returncode != 0:
            operation = label or Path(args[0]).name
            detail = result.stderr.strip() or result.stdout.strip() or "no process output"
            raise OrchestrationError(
                f"{operation} failed with exit code {result.returncode}: {detail[-4_000:]}"
            )
        return result

    @staticmethod
    def child_environment(overrides: dict[str, str] | None = None) -> dict[str, str]:
        environment = os.environ.copy()
        if overrides:
            environment.update(overrides)
        return environment

    @staticmethod
    def _terminate_process_group(process: subprocess.Popen[str]) -> tuple[str, str]:
        ProcessGroup.request_stop(process)
        try:
            return process.communicate(timeout=5)
        except subprocess.TimeoutExpired as graceful_timeout:
            ProcessGroup.force_stop(process)
            try:
                return process.communicate(timeout=5)
            except subprocess.TimeoutExpired as forced_timeout:
                return (
                    CommandRunner._timeout_output(
                        forced_timeout.stdout or graceful_timeout.stdout
                    ),
                    CommandRunner._timeout_output(
                        forced_timeout.stderr or graceful_timeout.stderr
                    ),
                )

    @staticmethod
    def _timeout_output(value: str | bytes | None) -> str:
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value or ""


class LoopbackHttpClient:
    """Makes requests without inheriting runner proxy settings."""

    def __init__(self) -> None:
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def json(
        self,
        url: str,
        *,
        method: str = "GET",
        bearer: str | None = None,
        payload: dict[str, Any] | None = None,
        timeout: int = 10,
    ) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with self._opener.open(request, timeout=timeout) as response:
                value = json.load(response)
        except (
            OSError,
            http.client.HTTPException,
            UnicodeError,
            json.JSONDecodeError,
        ) as error:
            raise OrchestrationError(f"loopback JSON request failed for {url}: {error}") from error
        if not isinstance(value, dict):
            raise OrchestrationError(f"loopback JSON response for {url} is not an object")
        return value

    def bytes(
        self,
        url: str,
        *,
        bearer: str,
        timeout: int = 10,
    ) -> tuple[bytes, dict[str, str]]:
        request = urllib.request.Request(
            url,
            headers={"Authorization": f"Bearer {bearer}"},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=timeout) as response:
                headers = {key.lower(): value for key, value in response.headers.items()}
                return response.read(), headers
        except (OSError, http.client.HTTPException) as error:
            raise OrchestrationError(
                f"loopback attachment request failed for {url}: {error}"
            ) from error

    def wait_until(
        self,
        operation: Callable[[], bool],
        *,
        timeout_seconds: int,
        description: str,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                if operation():
                    return
            except OrchestrationError as error:
                last_error = error
            time.sleep(1)
        suffix = f": {last_error}" if last_error else ""
        raise OrchestrationError(f"timed out waiting for {description}{suffix}")
