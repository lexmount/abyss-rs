#!/usr/bin/env python3
"""Run abyss-query against an isolated real SQLite+FTS backend binary.

The backend binary is supplied by the caller; this open repository does not
import backend implementation code or know private artifact locations.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Scenario:
    def __init__(self, query, backend, directory):
        self.query = str(query.resolve())
        self.backend = str(backend.resolve())
        self.directory = directory
        self.token = secrets.token_urlsafe(32)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.address = f"127.0.0.1:{listener.getsockname()[1]}"
        self.endpoint = f"http://{self.address}"
        self.environment = {
            **os.environ,
            "ABYSS_QUERY_CONFIG": str(directory / "profiles.json"),
            "QUERY_E2E_TOKEN": self.token,
            "ABYSS_BACKEND_ADDR": self.address,
            "ABYSS_BACKEND_ENV": "blackbox",
            "ABYSS_BACKEND_API_TOKEN_SHA256": hashlib.sha256(self.token.encode()).hexdigest(),
            "ABYSS_BACKEND_DATABASE_URL": str(directory / "data.sqlite"),
            "ABYSS_BACKEND_RUN_MIGRATIONS": "true",
        }
        self.environment.pop("ABYSS_QUERY_PROFILE", None)

    def cli(self, *arguments, code=0):
        process = subprocess.run(
            [self.query, *arguments], env=self.environment,
            capture_output=True, text=True, timeout=30, check=False,
        )
        require(process.returncode == code, f"query exit {process.returncode}: {process.stderr}")
        require(self.token not in process.stdout + process.stderr, "credential leaked")
        return json.loads(process.stdout if code == 0 else process.stderr)

    def http(self, path, payload=None):
        request = urllib.request.Request(
            self.endpoint + path,
            data=None if payload is None else json.dumps(payload).encode(),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.load(response)

    def run(self):
        with (self.directory / "backend.log").open("w+") as log:
            process = subprocess.Popen([self.backend], env=self.environment, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 30
                while True:
                    require(process.poll() is None, "backend exited during startup")
                    try:
                        self.http("/readyz")
                        break
                    except (OSError, urllib.error.URLError):
                        require(time.monotonic() < deadline, "backend readiness timeout")
                        time.sleep(0.1)
                self.verify()
            except Exception:
                log.seek(0)
                print(log.read())
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)

    def verify(self):
        events = []
        for side in ("request", "response"):
            events.append({
                "event_id": f"query-e2e-{side}", "observed_at": "2026-10-01T00:00:00Z",
                "device": {"host_name": "query-fixture", "platform": "linux", "os_version": "test"},
                "agent": {"name": "codex", "version": "test"}, "session_id": "query-session",
                "stream_id": "query-stream", "response_id": "query-response",
                "llm": {"provider": "openai", "model": "fixture-model"},
                "event_type": side, "text": f"queryfixture {side}",
                "token_usage": {"input_tokens": 2, "output_tokens": 3, "cache_read_tokens": 0,
                                "cache_write_tokens": 0, "reasoning_tokens": 0, "total_tokens": 5},
            })
        require(self.http("/v1/agent-usage/events", {"events": events})["accepted"] == 2, "ingestion")
        self.cli("profile", "add", "local", "--endpoint", self.endpoint, "--auth", "bearer",
                 "--token-env", "QUERY_E2E_TOKEN")
        self.cli("doctor")
        sessions = self.cli("sessions", "list", "--all", "--page-size", "1")["data"]
        require(len(sessions) == 1, "one persisted session")
        session_id = sessions[0]["session_pk"]
        for command in ("get", "outline", "trajectory"):
            require(self.cli("sessions", command, session_id)["data"]["session"]["session_pk"] == session_id,
                    f"session {command}")
        events = self.cli("events", "list", "--all", "--limit", "1", "--full")["data"]
        require(len(events) == 2, "event offset pagination")
        require(self.cli("events", "get", events[0]["id"])["data"]["text"].startswith("queryfixture"), "event content")
        hits = self.cli("search", "queryfixture")["data"]
        require(len(hits) == 1 and hits[0]["matches"], "real FTS search")
        require(self.cli("usage", "summary", "--group-by", "agent_name")["data"]["rows"], "usage rows")
        self.cli("profile", "add", "anonymous", "--endpoint", self.endpoint, "--auth", "none")
        require(self.cli("--profile", "anonymous", "doctor", code=3)["error"]["http_status"] == 401,
                "official local backend still requires authentication")
        print("abyss-query: real SQLite ingestion, reads, FTS, pagination and authentication passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", required=True, type=Path)
    parser.add_argument("--backend", required=True, type=Path, help="SQLite+FTS abyss-backend executable")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="abyss-query-e2e-") as directory:
        Scenario(args.query, args.backend, Path(directory)).run()


if __name__ == "__main__":
    main()
