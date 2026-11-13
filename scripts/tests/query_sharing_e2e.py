#!/usr/bin/env python3
"""Exercise session sharing against real product services with synthetic events.

Supply two distinct test principals and a disposable product deployment. The
scenario creates its own uniquely named session and revokes its share at the end.
Credentials and share capabilities are never printed. No service implementation
is mocked: the CLI, Identity authorization, database, and snapshot reads are real.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import uuid


class Scenario:
    def __init__(self, args, directory):
        self.args = args
        self.config = Path(directory) / "profiles.json"
        self.owner = args.owner_token_file.read_text().strip()
        self.recipient = args.recipient_token_file.read_text().strip()
        self.native_id = "query-sharing-" + uuid.uuid4().hex

    def http(self, path, *, principal="owner", method="GET", body=None,
             capability=None, status=200):
        headers = {"Content-Type": "application/json"}
        if principal != "anonymous":
            headers["Authorization"] = "Bearer " + getattr(self, principal)
        if capability is not None:
            headers["X-Abyss-Share-Token"] = capability
        request = urllib.request.Request(
            self.args.endpoint.rstrip("/") + "/" + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers, method=method,
        )
        try:
            response = urllib.request.urlopen(request, timeout=30)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == status, (path, response.status, status)
            content = response.read()
        return json.loads(content) if content else None

    def cli(self, args, *, profile="owner", code=0):
        environment = os.environ.copy()
        environment.pop("ABYSS_QUERY_CONFIG", None)
        environment.pop("ABYSS_QUERY_PROFILE", None)
        result = subprocess.run(
            [str(self.args.query), "--config", str(self.config), "--profile", profile, *args],
            capture_output=True, text=True, env=environment, timeout=40,
        )
        assert result.returncode == code, (args[0:2], result.returncode, code)
        if code:
            assert not result.stdout, "failure must not fabricate a link"
            return json.loads(result.stderr)
        assert not result.stderr, "successful sharing must not log its capability"
        return json.loads(result.stdout)

    def ingest(self, text):
        event = {
            "event_id": str(uuid.uuid4()),
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "device": {"host_name": self.native_id, "platform": "test", "os_version": "test"},
            "agent": {"name": "codex", "version": "synthetic"},
            "session_id": self.native_id,
            "llm": {"provider": "openai", "model": "synthetic"},
            "event_type": "request",
            "conversation": {"entries": [{"role": "user", "text": text}], "completeness": "complete"},
            "metadata": {},
        }
        result = self.http("v1/agent-usage/events", method="POST", body={"events": [event]})
        assert result["accepted"] == 1, "real ingestion must accept fixture"

    def run(self):
        for name, token_file in [("owner", self.args.owner_token_file), ("recipient", self.args.recipient_token_file)]:
            self.cli(["profile", "add", name, "--endpoint", self.args.endpoint,
                      "--auth", "bearer", "--token-file", str(token_file)], profile=name)
        self.cli(["profile", "add", "anonymous", "--endpoint", self.args.endpoint,
                  "--auth", "none"])
        marker = "Session share CLI synthetic evidence " + self.native_id
        self.ingest(marker)
        events = self.http("v1/agent-usage/events?" + urllib.parse.urlencode({"session_id": self.native_id}))
        session_pk = events["events"][0]["session_pk"]
        self.cli(["sessions", "share", session_pk], profile="anonymous", code=3)
        self.cli(["sessions", "share", session_pk], profile="recipient", code=5)
        self.cli(["sessions", "share", str(uuid.uuid4())], code=5)
        result = self.cli(["sessions", "share", session_pk])
        assert result["command"] == "sessions.share"
        link = urllib.parse.urlsplit(result["data"]["url"])
        share = result["data"]["share"]
        capability = urllib.parse.parse_qs(link.fragment)["token"][0]
        assert not link.query, "capability belongs in fragment only"
        endpoint = urllib.parse.urlsplit(self.args.endpoint)
        assert (link.scheme, link.netloc) == (endpoint.scheme, endpoint.netloc), "same API origin"
        assert link.path == "/shared/sessions/" + share["id"], "site-root browser route"
        assert share["status"] == "active" and share["expires_at"] > share["snapshot_at"]
        route = "v1/shared-sessions/" + share["id"]
        try:
            self.http(route + "/header", principal="anonymous", capability=capability, status=401)
            self.http(route + "/header", principal="recipient", status=404)
            snapshot = self.http(route + "/header", principal="recipient", capability=capability)
            assert snapshot["session_id"] == self.native_id, "share resolves the intended session"
            self.ingest("Later event excluded from existing share")
            frozen = self.http(route + "/header", principal="recipient", capability=capability)
            assert frozen == snapshot, "snapshot remains frozen after later ingestion"
            self.http(route + "/search?q=" + urllib.parse.quote(marker), principal="recipient", capability=capability)
            active = self.http("v1/agent-usage/sessions/" + session_pk + "/shares")
            assert len(active["shares"]) == 1, "exactly one successful CLI creation"
        finally:
            self.http("v1/agent-usage/sessions/" + session_pk + "/shares/" + share["id"], method="DELETE")
        self.http(route + "/header", principal="recipient", capability=capability, status=410)
        print(json.dumps({"result": "passed", "session_pk": session_pk,
                          "checks": ["authenticated_creation", "direct_url", "owner_scope",
                                     "missing_session", "recipient_sign_in", "capability_required",
                                     "snapshot_freeze", "single_creation", "revocation"]}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--query", type=Path, required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--owner-token-file", type=Path, required=True)
    parser.add_argument("--recipient-token-file", type=Path, required=True)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="query-sharing-e2e-") as directory:
        Scenario(args, directory).run()


if __name__ == "__main__":
    main()
