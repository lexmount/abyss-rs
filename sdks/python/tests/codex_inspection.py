"""Real-Codex SDK participant; records metadata and marker flags, not raw content."""

import json
import os
from pathlib import Path

from abyss_sdk.plugin import BrokerPlugin, RequestDecision


class Evidence:
    def __init__(self):
        self.path = Path(os.environ["ABYSS_SDK_CODEX_EVIDENCE"])
        self.allow_marker = os.environ["ABYSS_SDK_CODEX_ALLOW_MARKER"]
        self.block_marker = os.environ["ABYSS_SDK_CODEX_BLOCK_MARKER"]

    def record(self, value):
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(value) + "\n")

    @staticmethod
    def contains(conversation, marker):
        return conversation is not None and any(
            marker in entry.text for entry in conversation.entries
        )

    def inspect(self, context):
        if context.path == "/__abyss_sdk_ready":
            self.record({"kind": "ready"})
        agent = context.agent
        blocked = agent is not None and self.contains(agent.conversation, self.block_marker)
        for scenario, marker in [("allow", self.allow_marker), ("block", self.block_marker)]:
            if marker not in context.body.content:
                continue
            self.record(
                {
                    "kind": "inspection",
                    "case": scenario,
                    "request_id": context.request_id,
                    "harness": context.harness.id if context.harness else None,
                    "host": context.destination_host,
                    "server_name": context.server_name,
                    "source_process_absent": context.source_process is None,
                    "parsing_status": context.parsing_status,
                    "model": agent.model if agent else None,
                    "protocol": agent.protocol if agent else None,
                    "agent_has_marker": agent is not None
                    and self.contains(agent.conversation, marker),
                    "json_has_marker": marker in json.dumps(context.json),
                    "credential_headers_absent": not any(
                        name.lower()
                        in {"authorization", "proxy-authorization", "cookie", "x-api-key"}
                        for name, _ in context.headers
                    ),
                    "allow": not blocked,
                }
            )
        return RequestDecision(not blocked, "SDK black-box policy" if blocked else None)

    def event(self, event):
        self.record(
            {
                "kind": "event",
                "side": event.side,
                "agent": event.agent.name,
                "response_id": event.response_id,
                "session_id": event.session_id,
                "model": event.llm.model,
                "provider": event.llm.provider,
                "allow_marker": self.contains(event.conversation, self.allow_marker),
                "block_marker": self.contains(event.conversation, self.block_marker),
                "token_usage": vars(event.token_usage),
            }
        )


def main():
    evidence = Evidence()
    close = BrokerPlugin(
        "blackbox.codex.python",
        os.environ["ABYSS_SDK_CODEX_ENDPOINT"],
        on_agent_request=evidence.inspect,
        agent_events=True,
    ).run(evidence.event)
    assert close.code == 100, "broker did not close the SDK session cleanly"


if __name__ == "__main__":
    main()
