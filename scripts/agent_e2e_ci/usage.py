"""Exact usage accounting for captured traffic and completed Codex inference."""

from __future__ import annotations

import json
import sys
from typing import Any

from .process import OrchestrationError


class UsageAccounting:
    """Separate only explicitly marked prewarm traffic; retain every observation."""

    FIELDS = (
        "input_tokens",
        "cached_input_tokens",
        "cache_write_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
    )

    @classmethod
    def compare(
        cls,
        events: list[dict[str, Any]],
        completed_usage: tuple[dict[str, Any], ...],
    ) -> dict[str, Any]:
        prewarm = [event for event in events if cls._is_prewarm(event)]
        inference = [event for event in events if not cls._is_prewarm(event)]
        actual = cls._backend_totals(inference)
        expected = {
            field: sum(cls._counter(usage, field) for usage in completed_usage)
            for field in cls.FIELDS
        }
        # Codex 0.144.3 does not expose cache writes in turn.completed. Missing
        # evidence is not an explicit zero; input totals still include writes.
        unavailable_native_fields = [
            field
            for field in ("cache_write_input_tokens",)
            if any(field not in usage for usage in completed_usage)
        ]
        for field in unavailable_native_fields:
            del expected[field]
        difference = {field: actual[field] - expected[field] for field in expected}
        return {
            "scope": "completed_inference_excluding_explicit_prewarm",
            "backend_all_observed": cls._backend_totals(events),
            "backend_prewarm": cls._backend_totals(prewarm),
            "backend_inference": actual,
            "codex_completed_inference": expected,
            "unavailable_native_fields": unavailable_native_fields,
            "prewarm_event_ids": [event["event_id"] for event in prewarm],
            "difference": difference,
            "matches": bool(completed_usage)
            and bool(inference)
            and not any(difference.values()),
        }

    @staticmethod
    def _is_prewarm(event: dict[str, Any]) -> bool:
        metadata = event.get("metadata")
        return isinstance(metadata, dict) and metadata.get("purpose") == "prewarm"

    @classmethod
    def _backend_totals(cls, events: list[dict[str, Any]]) -> dict[str, int]:
        def total(field: str) -> int:
            return sum(cls._counter(event, field) for event in events)

        # Abyss stores disjoint input/cache counters; Codex input includes cache.
        return {
            "input_tokens": total("input_tokens")
            + total("cache_read_tokens")
            + total("cache_write_tokens"),
            "cached_input_tokens": total("cache_read_tokens"),
            "cache_write_input_tokens": total("cache_write_tokens"),
            "output_tokens": total("output_tokens"),
            "reasoning_output_tokens": total("reasoning_tokens"),
        }

    @staticmethod
    def _counter(value: dict[str, Any], field: str) -> int:
        count = value.get(field, 0)
        if type(count) is not int or count < 0:
            raise OrchestrationError(f"invalid usage counter: {field}")
        return count


def main() -> int:
    """Expose the same accounting to fixed-scenario shell black-box checks."""
    value = json.load(sys.stdin)
    result = UsageAccounting.compare(value["events"], tuple(value["completed_usage"]))
    print(json.dumps(result, sort_keys=True))
    return 0 if result["matches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
