"""Shared plugin contract compatibility tests."""

import json
import unittest
from pathlib import Path

from abyss_sdk import BrokerClient
from abyss_sdk.event import AgentEvent

FIXTURE = (
    Path(__file__).resolve().parents[3]
    / "specs"
    / "broker-plugin-protocol"
    / "v1"
    / "fixtures"
    / "agent-event.json"
)


class AgentEventContractTests(unittest.TestCase):
    def test_shared_fixture_decodes(self) -> None:
        event = AgentEvent.from_dict(json.loads(FIXTURE.read_text(encoding="utf-8")))

        self.assertEqual(event.event_id, "evt-123")
        self.assertEqual(event.llm.provider, "openai")
        self.assertEqual(event.tool_calls[0].name, "exec")

    def test_decoder_rejects_unknown_fields(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        fixture["metadata"] = {"private": True}

        with self.assertRaisesRegex(ValueError, "unknown fields"):
            AgentEvent.from_dict(fixture)

    def test_decoder_rejects_negative_token_usage(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        fixture["token_usage"]["input_tokens"] = -1

        with self.assertRaisesRegex(ValueError, "must not be negative"):
            AgentEvent.from_dict(fixture)


class BrokerClientContractTests(unittest.TestCase):
    def test_rejects_urls_outside_the_loopback_http_boundary(self) -> None:
        for base_url in ("http://example.com:18190", "https://127.0.0.1:18190"):
            with (
                self.subTest(base_url=base_url),
                self.assertRaisesRegex(ValueError, "HTTP and a loopback host"),
            ):
                BrokerClient(base_url=base_url)


if __name__ == "__main__":
    unittest.main()
