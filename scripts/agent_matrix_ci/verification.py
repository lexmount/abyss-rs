"""Deterministic cross-plane checks; missing evidence always fails the cell."""

from __future__ import annotations

import json
from collections import Counter

from scripts.agent_e2e_ci.usage import UsageAccounting

from .catalog import MatrixCase
from .transcript import Transcript


class MatrixVerifier:
    @staticmethod
    def verify(
        case: MatrixCase,
        native: Transcript,
        events: list[dict],
        *,
        marker: str,
        nonce: str,
        exit_code: int,
        timed_out: bool,
        healthy: bool,
        spool_empty: bool,
    ) -> dict:
        checks: dict[str, bool] = {}
        checks["client_completed"] = (
            exit_code == 0 and not timed_out and native.completed and not native.errors
        )
        checks["native_final_answer"] = (
            marker in native.final_text and nonce in native.final_text
        )
        checks["native_tool_result"] = any(
            nonce in output for output in native.tool_outputs
        )
        checks["events_received"] = len(events) >= 4
        checks["harness_identity"] = bool(events) and all(
            e.get("agent_name") == case.harness for e in events
        )
        checks["provider_identity"] = bool(events) and all(
            e.get("llm_provider") == case.event_provider for e in events
        )
        # Resolved, versioned names are allowed only when the requested alias is
        # their prefix (e.g. model -> model-YYYYMMDD); arbitrary fallback is not.
        checks["model_identity"] = bool(events) and all(
            isinstance(e.get("llm_model"), str)
            and (
                e["llm_model"] == case.model
                or e["llm_model"].startswith(case.model + "-")
            )
            for e in events
        )
        ids = [e.get("event_id") for e in events]
        checks["unique_events"] = (
            bool(ids)
            and all(isinstance(i, str) and i for i in ids)
            and len(ids) == len(set(ids))
        )
        pairs = {}
        for event in events:
            identity = event.get("response_id")
            pairs.setdefault(identity, Counter())[event.get("event_type")] += 1
        checks["request_response_pairs"] = bool(pairs) and all(
            isinstance(identity, str)
            and identity
            and counts == Counter({"request": 1, "response": 1})
            for identity, counts in pairs.items()
        )
        segments = [
            s for e in events for s in e.get("metadata", {}).get("content_segments", [])
        ]
        calls = {
            s.get("call_id")
            for s in segments
            if s.get("type") == "tool_call" and s.get("call_id")
        }
        results = {
            s.get("call_id")
            for s in segments
            if s.get("type") == "tool_result" and s.get("call_id")
        }
        checks["tool_roundtrip"] = bool(calls) and calls == results
        # pi's Responses adapter exposes `call_id|item_id` to DSH, then sends
        # only call_id back in function_call_output. Keep raw IDs in evidence
        # and compare the wire component only for this specific adapter.
        wire_call_ids = (
            {identity.split("|", 1)[0] for identity in native.call_ids}
            if case.harness == "deepseek-harness" and case.protocol == "responses"
            else native.call_ids
        )
        checks["native_tool_ids"] = (
            not wire_call_ids or wire_call_ids <= calls & results
        )
        checks["captured_tool_output"] = any(
            s.get("type") == "tool_result" and nonce in s.get("output", "")
            for s in segments
        )
        messages = [
            m
            for e in events
            for m in (e.get("conversation") or {}).get("messages", [])
        ]
        checks["captured_final_answer"] = any(
            m.get("role") == "assistant"
            and marker in m.get("text", "")
            and nonce in m.get("text", "")
            for m in messages
        )
        checks["complete_conversation"] = bool(events) and all(
            (e.get("conversation") or {}).get("completeness")
            == "complete"
            for e in events
        )
        # DSH pi Chat Completions does not transmit its session ID. Assert its
        # documented fallback rather than inventing a cross-request session.
        fallback = case.harness == "deepseek-harness" and case.protocol == "chat"
        checks["session_attribution"] = bool(events) and (
            all(str(e.get("session_id", "")).startswith("flow-") for e in events)
            if fallback
            else bool(native.session_id)
            and all(e.get("session_id") == native.session_id for e in events)
        )
        inference = [
            e for e in events if e.get("metadata", {}).get("purpose") != "prewarm"
        ]
        totals = UsageAccounting._backend_totals(inference)
        # Missing native fields are unavailable, never a fabricated zero. Input
        # and output must be present on every completed native inference.
        fields = (
            set.intersection(*(set(u) for u in native.usage)) if native.usage else set()
        )
        expected = {f: sum(u[f] for u in native.usage) for f in fields}
        difference = {f: totals[f] - expected[f] for f in fields}
        checks["exact_usage"] = (
            {"input_tokens", "output_tokens"} <= fields
            and not any(difference.values())
            and totals["input_tokens"] > 0
            and totals["output_tokens"] > 0
        )
        if case.harness == "hermes":
            checks["three_native_user_turns"] = len(native.turns) == 3 and all(
                turn["completed"]
                and turn["session_id"] == native.session_id
                and marker in turn["text"]
                and nonce in turn["text"]
                for turn in native.turns
            )
            checks["resumed_memory_without_tools"] = len(native.turns) == 3 and all(
                turn["tool_results"] == 0 for turn in native.turns[1:]
            )
            checks["three_captured_user_turns"] = {
                e.get("turn_index") for e in events
            } == {1, 2, 3} and all(
                any(
                    event.get("event_type") == "response"
                    and event.get("turn_index") == index
                    and marker in (event.get("text") or "")
                    and nonce in (event.get("text") or "")
                    for event in events
                )
                for index in (1, 2, 3)
            )
        checks["healthy_services"] = healthy
        checks["empty_delivery_spool"] = spool_empty
        return {
            "status": "pass" if all(checks.values()) else "fail",
            "case": case.as_dict(),
            "fixture": {"audit_marker": marker, "verification_code": nonce},
            "checks": checks,
            "failed_checks": [name for name, passed in checks.items() if not passed],
            "event_count": len(events),
            "session_mode": "per_request_flow_fallback"
            if fallback
            else "native_session",
            "usage": {
                "backend": totals,
                "native": expected,
                "difference": difference,
                "unavailable_native_fields": sorted(set(totals) - fields),
            },
            "native": {
                "completed": native.completed,
                "turns": native.turns,
                "usage_samples": native.usage,
                "session_id": native.session_id,
                "final_text": native.final_text,
                "tool_outputs": native.tool_outputs,
                "call_ids": sorted(native.call_ids),
                "wire_call_ids": sorted(wire_call_ids),
                "errors": native.errors,
                "exit_code": exit_code,
                "timed_out": timed_out,
            },
            "backend_events": events,
        }


class SecretRedactor:
    """Sanitize every uploaded string, including exception and provider output."""

    def __init__(self, *secrets: str | None) -> None:
        self.secrets = tuple(s for s in secrets if s)

    def text(self, value: str) -> str:
        for secret in self.secrets:
            value = value.replace(secret, "[REDACTED]")
        return value

    def document(self, value: dict) -> str:
        def redact(item):
            if isinstance(item, str):
                return self.text(item)
            if isinstance(item, dict):
                return {self.text(key): redact(child) for key, child in item.items()}
            if isinstance(item, list):
                return [redact(child) for child in item]
            return item

        return json.dumps(redact(value), ensure_ascii=False, indent=2) + "\n"
