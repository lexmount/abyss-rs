"""Credential-free artifacts and GitHub job summaries."""

from __future__ import annotations

import html
import json
import os
import shutil
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .model import Verdict


class ReportWriter:
    """Publishes only files that are safe to upload from the private runtime."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config

    def success(
        self,
        *,
        evidence: dict[str, Any],
        verdict: Verdict,
        preflight: dict[str, str],
    ) -> Path:
        root = self.config.artifact_root
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._write_json(root / "evidence.json", evidence)
        self._write_json(root / "verdict.json", verdict.raw)
        self._write_json(root / "runner-versions.json", preflight)
        plan_source = self.config.runtime_root / "coordinator" / "scenario-plan.json"
        if plan_source.is_file():
            shutil.copyfile(plan_source, root / "scenario-plan.json")
        summary = self._verdict_summary(verdict)
        summary_path = root / "summary.md"
        summary_path.write_text(summary, encoding="utf-8")
        self._append_github_summary(summary)
        return summary_path

    def failure(self, message: str, *, write_artifact: bool) -> None:
        root = self.config.artifact_root
        if write_artifact:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._write_json(
                root / "harness-error.json",
                {
                    "status": "harness_error",
                    "run_id": self.config.run_id,
                    "seed": self.config.seed,
                    "message": message,
                },
            )
        summary = "\n".join(
            (
                "## Codex agent-driven E2E",
                "",
                "- Status: `HARNESS ERROR`",
                f"- Run ID: `{self._safe(self.config.run_id)}`",
                f"- Seed: `{self.config.seed}`",
                "",
                f"> {self._safe(message)}",
                "",
            )
        )
        self._append_github_summary(summary)

    def _verdict_summary(self, verdict: Verdict) -> str:
        scenario_lines = []
        comparison_lines = []
        for result in verdict.raw["scenario_results"]:
            scenario_lines.append(
                f"- `{self._safe(str(result['id']))}`: `{self._safe(str(result['outcome']))}`"
            )
            comparison_lines.extend(("", f"#### `{self._safe(str(result['id']))}`", ""))
            for comparison in result["comparisons"]:
                comparison_lines.extend(
                    (
                        (
                            f"- **{self._excerpt(str(comparison['criterion']), 300)}**: "
                            f"`{self._safe(str(comparison['outcome']))}`"
                        ),
                        f"  - B actual: {self._excerpt(str(comparison['actual']), 800)}",
                        f"  - Backend: {self._excerpt(str(comparison['backend']), 800)}",
                        f"  - Reason: {self._excerpt(str(comparison['explanation']), 800)}",
                    )
                )
        issues = verdict.raw["issues"]
        issue_lines = [f"- {self._safe(str(issue))}" for issue in issues]
        lines = [
            "## Codex agent-driven E2E",
            "",
            f"- Status: `{verdict.status.value.upper()}`",
            f"- Run ID: `{self._safe(verdict.run_id)}`",
            f"- Seed: `{verdict.seed}`",
            "",
            self._safe(verdict.summary),
            "",
            "### Scenarios",
            "",
            *(scenario_lines or ["- No scenario results"]),
            "",
            "### Evidence comparisons",
            *comparison_lines,
        ]
        if issue_lines:
            lines.extend(("", "### Issues", "", *issue_lines))
        lines.extend(
            (
                "",
                "### Recommended action",
                "",
                self._safe(str(verdict.raw["recommended_action"])),
                "",
            )
        )
        return "\n".join(lines)

    @staticmethod
    def _write_json(path: Path, value: Any) -> None:
        path.write_text(
            json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @staticmethod
    def _safe(value: str) -> str:
        return html.escape(value.replace("\r", " ").strip(), quote=False)

    @classmethod
    def _excerpt(cls, value: str, limit: int) -> str:
        normalized = " ".join(value.replace("\r", " ").splitlines()).strip()
        if len(normalized) > limit:
            normalized = normalized[: limit - 1] + "…"
        return cls._safe(normalized)

    @staticmethod
    def _append_github_summary(summary: str) -> None:
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if not summary_path:
            return
        with Path(summary_path).open("a", encoding="utf-8") as handle:
            handle.write(summary)
