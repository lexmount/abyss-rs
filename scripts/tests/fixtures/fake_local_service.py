#!/usr/bin/env python3
"""Minimal loopback services used by the abyss-local black-box test."""

from __future__ import annotations

import argparse
import http.server
import os
import signal
import sys
from pathlib import Path


class HealthHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        if self.path in {"/healthz", "/readyz"}:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok\n")
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, message_format: str, *args: object) -> None:
        del message_format, args


def backend_address() -> tuple[str, int]:
    address = os.environ.get("ABYSS_BACKEND_ADDR", "")
    host, separator, port = address.rpartition(":")
    if separator == "" or host != "127.0.0.1":
        raise SystemExit("fake backend requires a loopback ABYSS_BACKEND_ADDR")
    database = os.environ.get("ABYSS_BACKEND_DATABASE_URL", "")
    digest = os.environ.get("ABYSS_BACKEND_API_TOKEN_SHA256", "")
    if database == "" or len(digest) != 64:
        raise SystemExit("fake backend requires database and token digest settings")
    return host, int(port)


def dashboard_address(argv: list[str]) -> tuple[str, int]:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--backend", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.host != "127.0.0.1" or not args.backend.startswith("http://127.0.0.1:"):
        raise SystemExit("fake dashboard requires loopback origins")
    if not args.token_file.is_file() or args.token_file.read_text().strip() == "":
        raise SystemExit("fake dashboard requires a token file")
    return args.host, args.port


def main() -> None:
    executable = Path(os.path.basename(sys.argv[0])).name
    if executable == "abyss-backend":
        address = backend_address()
    elif executable == "abyss-dashboard":
        address = dashboard_address(sys.argv[1:])
    elif executable == "port-blocker":
        address = ("127.0.0.1", int(sys.argv[1]))
    else:
        raise SystemExit(f"unsupported fake service name: {executable}")

    server = http.server.ThreadingHTTPServer(address, HealthHandler)

    def stop(_signum: int, _frame: object) -> None:
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
