"""Backend correlation and credential-free evidence bundle construction."""

from __future__ import annotations

import hashlib
import json
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .assets import FixtureManifest
from .codex import CodexBResult
from .config import RuntimeConfig
from .model import ScenarioPlan
from .process import LoopbackHttpClient, OrchestrationError
from .stack import TestStack


MAX_EVIDENCE_STRING_BYTES = 12 * 1024


@dataclass(frozen=True)
class ScenarioExecution:
    """One generated scenario, immutable fixtures, and Codex B observations."""

    result: CodexBResult
    fixtures: FixtureManifest


class BackendEvidenceCollector:
    """Polls the fresh Backend and correlates events without judging correctness."""

    def __init__(self, config: RuntimeConfig, http: LoopbackHttpClient, stack: TestStack) -> None:
        self.config = config
        self.http = http
        self.stack = stack

    def collect(self, executions: list[ScenarioExecution]) -> dict[str, Any]:
        all_events = self._wait_for_stable_events(executions)
        scenario_events: dict[str, list[dict[str, Any]]] = {}
        attributed_event_ids: set[str] = set()
        for execution in executions:
            selected = self._events_for(execution.result, all_events)
            scenario_events[execution.result.scenario_id] = selected
            attributed_event_ids.update(
                event_id
                for event in selected
                if isinstance((event_id := event.get("event_id")), str)
            )
        unattributed = [
            event
            for event in all_events
            if not isinstance(event.get("event_id"), str)
            or event.get("event_id") not in attributed_event_ids
        ]
        return {
            "total_event_count": len(all_events),
            "scenario_events": scenario_events,
            "unattributed_events": unattributed,
            "attachments": self._download_attachments(all_events),
        }

    def _wait_for_stable_events(
        self,
        executions: list[ScenarioExecution],
    ) -> list[dict[str, Any]]:
        deadline = time.monotonic() + self.config.event_timeout_seconds
        previous_identity: tuple[str, ...] | None = None
        stable_polls = 0
        latest: list[dict[str, Any]] = []
        while time.monotonic() < deadline:
            try:
                latest = self._fetch_events()
            except OrchestrationError:
                time.sleep(1)
                continue
            required = [
                execution.result
                for execution in executions
                if execution.result.completed_usage and execution.result.exit_code == 0
            ]
            all_found = all(self._events_for(result, latest) for result in required)
            identity = tuple(
                sorted(
                    event_id
                    for event in latest
                    if isinstance((event_id := event.get("event_id")), str)
                )
            )
            if all_found and identity == previous_identity:
                stable_polls += 1
            else:
                stable_polls = 0
            if all_found and stable_polls >= 5:
                return latest
            previous_identity = identity
            time.sleep(1)
        return latest

    def _fetch_events(self) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode(
            {
                "agent_name": "codex",
                "llm_provider": "openai",
                "limit": "1000",
            }
        )
        response = self.http.json(
            f"{self.stack.backend_base_url}/v1/agent-usage/events?{query}",
            bearer=self.stack.native_token,
        )
        events = response.get("events")
        if not isinstance(events, list) or not all(isinstance(event, dict) for event in events):
            raise OrchestrationError("Backend raw-event response has an invalid events array")
        return events

    @staticmethod
    def _events_for(result: CodexBResult, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        session_ids: set[str] = set()
        if result.thread_id:
            session_ids.add(result.thread_id)
        for event in events:
            text = event.get("text")
            session_id = event.get("session_id")
            if isinstance(text, str) and result.marker in text and isinstance(session_id, str):
                session_ids.add(session_id)
        if session_ids:
            return [event for event in events if event.get("session_id") in session_ids]
        return [
            event
            for event in events
            if isinstance(event.get("text"), str) and result.marker in event["text"]
        ]

    def _download_attachments(self, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
        downloaded: list[dict[str, Any]] = []
        seen: set[str] = set()
        for event in events:
            attachments = event.get("attachments")
            if not isinstance(attachments, list):
                continue
            for attachment in attachments:
                if not isinstance(attachment, dict):
                    continue
                attachment_id = attachment.get("id")
                if not isinstance(attachment_id, str) or attachment_id in seen:
                    continue
                seen.add(attachment_id)
                record: dict[str, Any] = {
                    "attachment_id": attachment_id,
                    "event_id": event.get("event_id"),
                    "declared": attachment,
                }
                if attachment.get("content_available") is True:
                    try:
                        content, headers = self.http.bytes(
                            (
                                f"{self.stack.backend_base_url}/v1/agent-usage/attachments/"
                                f"{urllib.parse.quote(attachment_id)}"
                            ),
                            bearer=self.stack.native_token,
                        )
                        record["download"] = {
                            "succeeded": True,
                            "content_type": headers.get("content-type"),
                            "byte_size": len(content),
                            "sha256": hashlib.sha256(content).hexdigest(),
                        }
                    except OrchestrationError as error:
                        record["download"] = {"succeeded": False, "error": str(error)}
                else:
                    record["download"] = {
                        "succeeded": False,
                        "reason": "Backend reported content_available=false",
                    }
                downloaded.append(record)
        return downloaded


class EvidenceBuilder:
    """Combines both observation planes without making semantic assertions."""

    def __init__(self, config: RuntimeConfig, stack: TestStack) -> None:
        self.config = config
        self.stack = stack

    def build(
        self,
        plan: ScenarioPlan,
        executions: list[ScenarioExecution],
        backend: dict[str, Any],
        codex_version: str,
    ) -> dict[str, Any]:
        self.stack.flush_broker_log()
        evidence = {
            "contract_version": 1,
            "run": {
                "run_id": self.config.run_id,
                "seed": self.config.seed,
                "codex_version": codex_version,
                "topology": (
                    "Codex B -> explicit abyss-broker proxy -> OpenAI; "
                    "broker hook -> delivery plugin -> fresh Backend -> fresh PostgreSQL"
                ),
                "only_codex_b_received_proxy_environment": True,
                "long_string_evidence": (
                    "UTF-8 strings larger than 12288 bytes are represented by bounded "
                    "prefix/suffix excerpts plus byte size and SHA-256."
                ),
            },
            "scenario_plan": self._plan_value(plan),
            "executions": [
                {
                    "scenario_id": execution.result.scenario_id,
                    "fixtures": execution.fixtures.as_dict(),
                    "codex_b": execution.result.as_dict(),
                    "backend_events": backend["scenario_events"].get(
                        execution.result.scenario_id, []
                    ),
                }
                for execution in executions
            ],
            "backend": {
                "total_event_count": backend["total_event_count"],
                "unattributed_events": backend["unattributed_events"],
                "attachments": backend["attachments"],
            },
            "infrastructure": {
                "health": self.stack.health_snapshot(),
                "spool": self._spool_evidence(),
                "broker_diagnostics": self._broker_diagnostics(),
            },
        }
        compacted = self._compact(evidence)
        if not isinstance(compacted, dict):
            raise OrchestrationError("internal evidence compaction changed the bundle root")
        return compacted

    @staticmethod
    def _plan_value(plan: ScenarioPlan) -> dict[str, Any]:
        return {
            "run_id": plan.run_id,
            "seed": plan.seed,
            "scenarios": [
                {
                    "id": scenario.scenario_id,
                    "title": scenario.title,
                    "objective": scenario.objective,
                    "prompt": scenario.prompt,
                    "files": [
                        {"path": fixture.path, "content": fixture.content}
                        for fixture in scenario.files
                    ],
                    "image": {
                        "width": scenario.image.width,
                        "height": scenario.image.height,
                        "pattern": scenario.image.pattern,
                        "palette": list(scenario.image.palette),
                    },
                    "coverage_targets": list(scenario.coverage_targets),
                    "rationale": scenario.rationale,
                }
                for scenario in plan.scenarios
            ],
        }

    def _spool_evidence(self) -> dict[str, Any]:
        path = self.stack.spool_path
        if not path.exists():
            return {"exists": False, "byte_size": 0, "record_count": 0}
        content = path.read_bytes()
        return {
            "exists": True,
            "byte_size": len(content),
            "record_count": len([line for line in content.splitlines() if line.strip()]),
        }

    def _broker_diagnostics(self) -> dict[str, Any]:
        path = self.stack.broker_log_path
        if not path.is_file():
            return {"log_available": False, "suspicious_lines": []}
        text = path.read_text(encoding="utf-8", errors="replace")
        suspicious = []
        for line in text.splitlines():
            normalized = line.lower()
            if "spool" in normalized or (
                "upload" in normalized and any(word in normalized for word in ("fail", "error"))
            ):
                suspicious.append(self._redact(line)[-2_000:])
        return {
            "log_available": True,
            "suspicious_lines": suspicious[-100:],
        }

    def _redact(self, value: str) -> str:
        redacted = value.replace(self.stack.native_token, "[REDACTED_NATIVE_TOKEN]")
        if self.stack.broker_token:
            redacted = redacted.replace(self.stack.broker_token, "[REDACTED_BROKER_TOKEN]")
        return redacted

    @classmethod
    def _compact(cls, value: Any) -> Any:
        if isinstance(value, str):
            encoded = value.encode("utf-8")
            if len(encoded) <= MAX_EVIDENCE_STRING_BYTES:
                return value
            excerpt_size = MAX_EVIDENCE_STRING_BYTES // 2
            prefix = encoded[:excerpt_size].decode("utf-8", errors="replace")
            suffix = encoded[-excerpt_size:].decode("utf-8", errors="replace")
            return {
                "evidence_encoding": "truncated_utf8",
                "byte_size": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "prefix": prefix,
                "suffix": suffix,
            }
        if isinstance(value, list):
            return [cls._compact(item) for item in value]
        if isinstance(value, tuple):
            return [cls._compact(item) for item in value]
        if isinstance(value, dict):
            return {key: cls._compact(item) for key, item in value.items()}
        return value


def write_evidence(path: Path, evidence: dict[str, Any]) -> None:
    """Writes the credential-free bundle consumed by Codex A and CI artifacts."""
    path.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
