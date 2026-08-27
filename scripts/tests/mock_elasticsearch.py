#!/usr/bin/env python3
"""Small Elasticsearch HTTP contract double for backend black-box tests."""

from __future__ import annotations

import argparse
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


INDEX_PATH = "/abyss_usage_events"
HIGHLIGHT_START = "[[[ABYSS_SEARCH_HIGHLIGHT_START]]]"
HIGHLIGHT_END = "[[[ABYSS_SEARCH_HIGHLIGHT_END]]]"
SEARCHABLE_FIELDS = (
    "content",
    "commands",
    "file_paths",
    "tool_names",
    "tool_content",
    "session_id",
)


class ElasticsearchDouble(ThreadingHTTPServer):
    """Thread-safe in-memory document store with the required ES endpoints."""

    def __init__(self, address: tuple[str, int]) -> None:
        super().__init__(address, ElasticsearchHandler)
        self.index_ready = False
        self.documents: dict[str, dict[str, Any]] = {}
        self.lock = threading.Lock()


class ElasticsearchHandler(BaseHTTPRequestHandler):
    server: ElasticsearchDouble

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != INDEX_PATH:
            self.send_error(404)
            return
        with self.server.lock:
            ready = self.server.index_ready
        self.send_response(200 if ready else 404)
        self.end_headers()

    def do_PUT(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != INDEX_PATH:
            self.send_error(404)
            return
        self._read_body()
        with self.server.lock:
            self.server.index_ready = True
        self._json_response(200, {"acknowledged": True})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path == "/_bulk":
            self._bulk()
            return
        if self.path == f"{INDEX_PATH}/_search":
            self._search()
            return
        self.send_error(404)

    def _bulk(self) -> None:
        lines = [line for line in self._read_body().splitlines() if line]
        items: list[dict[str, Any]] = []
        index = 0
        with self.server.lock:
            while index < len(lines):
                action = json.loads(lines[index])
                index += 1
                if "index" in action:
                    metadata = action["index"]
                    document = json.loads(lines[index])
                    index += 1
                    self.server.documents[metadata["_id"]] = document
                    items.append({"index": {"status": 201}})
                elif "delete" in action:
                    metadata = action["delete"]
                    existed = self.server.documents.pop(metadata["_id"], None)
                    items.append({"delete": {"status": 200 if existed else 404}})
                else:
                    items.append(
                        {
                            "unknown": {
                                "status": 400,
                                "error": {"reason": "unsupported bulk action"},
                            }
                        }
                    )
        self._json_response(
            200,
            {
                "errors": any(next(iter(item.values()))["status"] >= 400 for item in items),
                "items": items,
            },
        )

    def _search(self) -> None:
        request = json.loads(self._read_body())
        query_text = request["query"]["bool"]["must"][0]["multi_match"]["query"]
        filters = request["query"]["bool"].get("filter", [])
        with self.server.lock:
            documents = list(self.server.documents.values())
        matching = [
            document
            for document in documents
            if matches_filters(document, filters) and matches_query(document, query_text)
        ]
        grouped: dict[str, list[dict[str, Any]]] = {}
        for document in matching:
            grouped.setdefault(document["session_pk"], []).append(document)

        start = int(request.get("from", 0))
        size = int(request.get("size", 20))
        selected = list(grouped.items())[start : start + size]
        outer_hits = [collapsed_hit(session_pk, events, query_text) for session_pk, events in selected]
        self._json_response(
            200,
            {
                "aggregations": {"session_count": {"value": len(grouped)}},
                "hits": {"hits": outer_hits},
            },
        )

    def _read_body(self) -> str:
        length = int(self.headers.get("content-length", "0"))
        return self.rfile.read(length).decode("utf-8")

    def _json_response(self, status: int, body: dict[str, Any]) -> None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def matches_filters(document: dict[str, Any], filters: list[dict[str, Any]]) -> bool:
    for clause in filters:
        if "term" in clause:
            for field, expected in clause["term"].items():
                if document.get(field) != expected:
                    return False
        if "range" in clause:
            for field, bounds in clause["range"].items():
                value = document.get(field)
                if value is None:
                    return False
                if "gte" in bounds and value < bounds["gte"]:
                    return False
                if "lt" in bounds and value >= bounds["lt"]:
                    return False
    return True


def matches_query(document: dict[str, Any], query: str) -> bool:
    query = query.casefold()
    return any(query in value.casefold() for value in searchable_values(document))


def searchable_values(document: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for field in SEARCHABLE_FIELDS:
        value = document.get(field)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(item for item in value if isinstance(item, str))
    return values


def collapsed_hit(
    session_pk: str,
    events: list[dict[str, Any]],
    query: str,
) -> dict[str, Any]:
    matches = []
    for event in events[:3]:
        highlight: dict[str, list[str]] = {}
        for field in SEARCHABLE_FIELDS:
            value = event.get(field)
            field_values = [value] if isinstance(value, str) else value or []
            fragments = [highlighted_fragment(item, query) for item in field_values]
            fragments = [fragment for fragment in fragments if fragment is not None]
            if fragments:
                highlight[field] = fragments[:2]
        matches.append(
            {
                "_source": {
                    "event_pk": event["event_pk"],
                    "turn_pk": event["turn_pk"],
                    "turn_index": event["turn_index"],
                    "event_type": event["event_type"],
                    "llm_provider": event["llm_provider"],
                    "llm_model": event["llm_model"],
                    "observed_at": event["observed_at"],
                },
                "highlight": highlight,
            }
        )
    return {
        "_source": {"session_pk": session_pk},
        "inner_hits": {
            "matches": {
                "hits": {
                    "total": {"value": len(events), "relation": "eq"},
                    "hits": matches,
                }
            }
        },
    }


def highlighted_fragment(value: Any, query: str) -> str | None:
    if not isinstance(value, str):
        return None
    match = re.search(re.escape(query), value, flags=re.IGNORECASE)
    if match is None:
        return None
    start = max(0, match.start() - 100)
    end = min(len(value), match.end() + 100)
    fragment = value[start:end]
    local_start = match.start() - start
    local_end = match.end() - start
    return (
        fragment[:local_start]
        + HIGHLIGHT_START
        + fragment[local_start:local_end]
        + HIGHLIGHT_END
        + fragment[local_end:]
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", default="127.0.0.1:0")
    parser.add_argument("--ready-file", required=True)
    args = parser.parse_args()
    host, port_text = args.listen.rsplit(":", 1)
    server = ElasticsearchDouble((host, int(port_text)))
    bound_host, bound_port = server.server_address
    Path(args.ready_file).write_text(
        f"http://{bound_host}:{bound_port}", encoding="utf-8"
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
