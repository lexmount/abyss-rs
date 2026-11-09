"""Regression checks for explicit prewarm and exact inference accounting."""

from __future__ import annotations

import unittest

from scripts.agent_e2e_ci.process import OrchestrationError
from scripts.agent_e2e_ci.usage import UsageAccounting


class UsageAccountingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.events = [
            {
                "event_id": "warm",
                "purpose": "prewarm",
                "token_usage": {
                    "input_tokens": 10790,
                    "output_tokens": 0,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                    "reasoning_tokens": 0,
                    "total_tokens": 10790,
                },
            },
            {
                "event_id": "request",
                "purpose": None,
                "token_usage": {
                    "input_tokens": 8,
                    "output_tokens": 0,
                    "cache_read_tokens": 2,
                    "cache_write_tokens": 1,
                    "reasoning_tokens": 0,
                    "total_tokens": 11,
                },
            },
            {
                "event_id": "response",
                "purpose": None,
                "token_usage": {
                    "input_tokens": 0,
                    "output_tokens": 7,
                    "cache_read_tokens": 0,
                    "cache_write_tokens": 0,
                    "reasoning_tokens": 3,
                    "total_tokens": 7,
                },
            },
        ]
        self.native = (
            {
                "input_tokens": 11,
                "cached_input_tokens": 2,
                "cache_write_input_tokens": 1,
                "output_tokens": 7,
                "reasoning_output_tokens": 3,
            },
        )

    def test_prewarm_retained_separately_without_double_counting_subsets(self) -> None:
        result = UsageAccounting.compare(self.events, self.native)
        self.assertTrue(result["matches"])
        self.assertEqual(result["prewarm_event_ids"], ["warm"])
        self.assertEqual(result["backend_all_observed"]["input_tokens"], 10801)
        self.assertEqual(result["backend_prewarm"]["input_tokens"], 10790)
        self.assertEqual(result["backend_inference"]["input_tokens"], 11)
        self.assertEqual(result["backend_inference"]["output_tokens"], 7)
        self.assertEqual(result["backend_inference"]["reasoning_output_tokens"], 3)

    def test_unmarked_initial_and_compaction_calls_are_not_excluded(self) -> None:
        for purpose in (None, "compaction", "session_title"):
            with self.subTest(purpose=purpose):
                self.events[0]["purpose"] = purpose
                result = UsageAccounting.compare(self.events, self.native)
                self.assertFalse(result["matches"])
                self.assertEqual(result["difference"]["input_tokens"], 10790)
                self.assertEqual(result["prewarm_event_ids"], [])

    def test_prewarm_is_independent_of_event_order_and_token_amount(self) -> None:
        self.events[0]["token_usage"]["input_tokens"] = 19
        result = UsageAccounting.compare(list(reversed(self.events)), self.native)
        self.assertTrue(result["matches"])
        self.assertEqual(result["backend_prewarm"]["input_tokens"], 19)

    def test_one_token_mismatch_remains_a_failure(self) -> None:
        self.events[1]["token_usage"]["input_tokens"] = 9
        result = UsageAccounting.compare(self.events, self.native)
        self.assertFalse(result["matches"])
        self.assertEqual(result["difference"]["input_tokens"], 1)

    def test_multiple_completed_turns_sum_exactly(self) -> None:
        result = UsageAccounting.compare(self.events * 2, self.native * 2)
        self.assertTrue(result["matches"])
        self.assertEqual(result["codex_completed_inference"]["input_tokens"], 22)

    def test_unreported_cache_writes_are_not_assumed_zero(self) -> None:
        del self.native[0]["cache_write_input_tokens"]
        result = UsageAccounting.compare(self.events, self.native)
        self.assertTrue(result["matches"])
        self.assertEqual(result["unavailable_native_fields"], ["cache_write_input_tokens"])
        self.assertNotIn("cache_write_input_tokens", result["difference"])
        self.assertNotIn("cache_write_input_tokens", result["codex_completed_inference"])
        self.assertEqual(result["backend_inference"]["cache_write_input_tokens"], 1)
        self.events[1]["token_usage"]["cache_write_tokens"] = 2
        result = UsageAccounting.compare(self.events, self.native)
        self.assertFalse(result["matches"])
        self.assertEqual(result["difference"]["input_tokens"], 1)

    def test_explicit_zero_cache_writes_must_match(self) -> None:
        self.native[0]["cache_write_input_tokens"] = 0
        result = UsageAccounting.compare(self.events, self.native)
        self.assertFalse(result["matches"])
        self.assertEqual(result["unavailable_native_fields"], [])
        self.assertEqual(result["difference"]["cache_write_input_tokens"], 1)

    def test_partial_cache_write_reporting_does_not_claim_an_exact_total(self) -> None:
        second = dict(self.native[0])
        del second["cache_write_input_tokens"]
        result = UsageAccounting.compare(self.events * 2, (self.native[0], second))
        self.assertTrue(result["matches"])
        self.assertEqual(result["unavailable_native_fields"], ["cache_write_input_tokens"])
        self.assertNotIn("cache_write_input_tokens", result["codex_completed_inference"])
        self.assertEqual(result["backend_inference"]["cache_write_input_tokens"], 2)
        self.native[0]["cache_write_input_tokens"] = None
        with self.assertRaises(OrchestrationError):
            UsageAccounting.compare(self.events * 2, (self.native[0], second))

    def test_missing_inference_evidence_cannot_pass(self) -> None:
        self.assertFalse(UsageAccounting.compare(self.events, ())["matches"])
        self.assertFalse(UsageAccounting.compare([], ({},))["matches"])
        self.assertFalse(UsageAccounting.compare(self.events[:1], ({},))["matches"])

    def test_invalid_counters_fail_instead_of_becoming_zero(self) -> None:
        for count in (True, None, -1, 2.5, "2"):
            with self.subTest(count=count):
                self.events[1]["token_usage"]["input_tokens"] = count
                with self.assertRaises(OrchestrationError):
                    UsageAccounting.compare(self.events, self.native)

    def test_missing_backend_usage_cannot_become_zero(self) -> None:
        for usage in (None, {}, {"input_tokens": 0}, "invalid"):
            with self.subTest(usage=usage), self.assertRaises(OrchestrationError):
                UsageAccounting.compare([{"token_usage": usage}], ({},))
        with self.assertRaises(OrchestrationError):
            UsageAccounting.compare([{"input_tokens": 0}], ({},))


if __name__ == "__main__":
    unittest.main()
