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
        event = AgentEvent.from_dict(fixture)
        self.assertEqual(event.purpose, "prewarm")
        self.assertEqual(event.token_usage.input_tokens, fixture["token_usage"]["input_tokens"])

    def test_shared_fixture_decodes(self) -> None:
        event = AgentEvent.from_dict(json.loads(FIXTURE.read_text(encoding="utf-8")))

        self.assertEqual(event.event_id, "evt-123")
        self.assertEqual(event.llm.provider, "openai")
        self.assertEqual(event.response_id, "resp-123")
        self.assertEqual(event.previous_response_id, "resp-122")
        self.assertEqual(event.purpose, "session_title")
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
        self.assertEqual(event.headers[1].name, "x-request-id")
        self.assertEqual(event.headers[1].value, "req-123")
        self.assertIsNone(event.headers[1].value_base64)
        self.assertFalse(hasattr(event, "turn_index"))
        for field in ("text", "tool_calls", "tool_results"):
            self.assertFalse(hasattr(event, field))

    def test_optional_context_and_entry_identities(self) -> None:
        fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
        for field in (
            "response_id",
            "previous_response_id",
            "purpose",
            "conversation",
            "headers",
        ):
            fixture.pop(field)
        event = AgentEvent.from_dict(fixture)
        self.assertIsNone(event.response_id)
        self.assertEqual(event.headers, ())
        self.assertIsNone(event.conversation)
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
            (("text",), "hello"),
            (("tool_calls",), []),
            (("tool_results",), []),
            (("turn_id",), "turn-1"),
            (("naming_thread",), True),
            (("stream_id",), "thread-1"),
            (("session_title",), "title"),
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
            (("headers", 0, "value"), 1),
            (("headers", 0, "value_base64"), "dg=="),
            (("headers", 0, "raw"), True),
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
