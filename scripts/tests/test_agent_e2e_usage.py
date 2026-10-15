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
                "input_tokens": 10790,
                "metadata": {"purpose": "prewarm"},
            },
            {
                "event_id": "request",
                "input_tokens": 8,
                "cache_read_tokens": 2,
                "cache_write_tokens": 1,
            },
            {"event_id": "response", "output_tokens": 7, "reasoning_tokens": 3},
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
        for metadata in ({}, {"purpose": "compaction"}, {"purpose": "session_title"}):
            with self.subTest(metadata=metadata):
                self.events[0]["metadata"] = metadata
                result = UsageAccounting.compare(self.events, self.native)
                self.assertFalse(result["matches"])
                self.assertEqual(result["difference"]["input_tokens"], 10790)
                self.assertEqual(result["prewarm_event_ids"], [])

    def test_prewarm_is_independent_of_event_order_and_token_amount(self) -> None:
        self.events[0]["input_tokens"] = 19
        result = UsageAccounting.compare(list(reversed(self.events)), self.native)
        self.assertTrue(result["matches"])
        self.assertEqual(result["backend_prewarm"]["input_tokens"], 19)

    def test_one_token_mismatch_remains_a_failure(self) -> None:
        self.events[1]["input_tokens"] = 9
        result = UsageAccounting.compare(self.events, self.native)
        self.assertFalse(result["matches"])
        self.assertEqual(result["difference"]["input_tokens"], 1)

    def test_multiple_completed_turns_sum_exactly(self) -> None:
        result = UsageAccounting.compare(self.events * 2, self.native * 2)
        self.assertTrue(result["matches"])
        self.assertEqual(result["codex_completed_inference"]["input_tokens"], 22)

    def test_missing_inference_evidence_cannot_pass(self) -> None:
        self.assertFalse(UsageAccounting.compare(self.events, ())["matches"])
        self.assertFalse(UsageAccounting.compare([], ({},))["matches"])
        self.assertFalse(UsageAccounting.compare(self.events[:1], ({},))["matches"])

    def test_invalid_counters_fail_instead_of_becoming_zero(self) -> None:
        for count in (True, None, -1, 2.5, "2"):
            with self.subTest(count=count):
                self.events[1]["input_tokens"] = count
                with self.assertRaises(OrchestrationError):
                    UsageAccounting.compare(self.events, self.native)


if __name__ == "__main__":
    unittest.main()
