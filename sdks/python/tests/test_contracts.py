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
    def test_explicit_prewarm_retains_observed_usage(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        fixture["purpose"] = "prewarm"
        fixture.pop("session_title")
        event = AgentEvent.from_dict(fixture)
        self.assertEqual(event.purpose, "prewarm")
        self.assertEqual(event.token_usage.input_tokens, fixture["token_usage"]["input_tokens"])

    def test_shared_fixture_decodes(self) -> None:
        event = AgentEvent.from_dict(json.loads(FIXTURE.read_text(encoding="utf-8")))

        self.assertEqual(event.event_id, "evt-123")
        self.assertEqual(event.turn_id, "turn-123")
        self.assertEqual(event.llm.provider, "openai")
        self.assertEqual(event.tool_calls[0].name, "exec")
        self.assertTrue(event.naming_thread)
        self.assertEqual(event.stream_id, "thread-123")
        self.assertEqual(event.response_id, "resp-123")
        self.assertEqual(event.previous_response_id, "resp-122")
        self.assertEqual(event.purpose, "session_title")
        self.assertEqual(event.session_title, "Repository overview")
        self.assertIsNotNone(event.conversation)
        self.assertEqual(
            [entry.role for entry in event.conversation.entries],
            ["reasoning", "assistant", "tool_call"],
        )
        self.assertEqual(event.conversation.entries[2].call_id, "call-123")
        self.assertEqual(event.conversation.entries[2].name, "exec")
        self.assertEqual(event.conversation.entries[0].item_id, "rs-123")
        self.assertEqual(event.omitted, ())
        self.assertEqual(event.conversation.completeness, "complete")
        self.assertFalse(hasattr(event, "turn_index"))

    def test_optional_context_and_entry_identities(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for field in (
            "turn_id",
            "naming_thread",
            "stream_id",
            "response_id",
            "previous_response_id",
            "purpose",
            "session_title",
            "conversation",
        ):
            fixture.pop(field)
        event = AgentEvent.from_dict(fixture)
        self.assertIsNone(event.turn_id)
        self.assertIsNone(event.conversation)
        self.assertFalse(event.naming_thread)
        fixture["purpose"] = "compaction"
        fixture["omitted"] = ["conversation_text"]
        fixture["conversation"] = {
            "entries": [{"role": "unknown", "text": ""}],
            "completeness": "partial",
        }
        event = AgentEvent.from_dict(fixture)
        self.assertEqual(event.purpose, "compaction")
        self.assertIsNone(event.conversation.entries[0].item_id)
        self.assertIsNone(event.conversation.entries[0].call_id)
        self.assertEqual(event.omitted, ("conversation_text",))

    def test_rejects_obsolete_fields_and_malformed_content(self) -> None:
        for path, value in (
            (("turn_index",), 1),
            (("naming_thread",), 1),
            (("stream_id",), 1),
            (("purpose",), "other"),
            (("omitted",), ["text"]),
            (("conversation", "entries", 0, "role"), "tool"),
            (("conversation", "entries", 0, "blocks"), []),
            (("conversation", "entries", 0, "text"), 1),
            (("conversation", "entries", 0, "item_id"), 1),
            (("conversation", "entries"), {}),
            (("conversation", "completeness"), "failed"),
            (("conversation", "messages"), []),
            (("conversation", "instructions_present"), True),
            (("conversation", "policy_omitted"), False),
        ):
            with self.subTest(path=path):
                fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
                parent = fixture
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = value
                with self.assertRaises((TypeError, ValueError)):
                    AgentEvent.from_dict(fixture)

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
