"""Codex A generation/judging and proxied Codex B execution boundaries."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from string import Template
from typing import Any

from .config import RuntimeConfig
from .model import ContractError, Scenario, ScenarioPlan, Verdict
from .process import CommandResult, CommandRunner, OrchestrationError
from .stack import TestStack


@dataclass(frozen=True)
class CodexBResult:
    """Observable local behavior of one Codex B process."""

    scenario_id: str
    marker: str
    exit_code: int
    timed_out: bool
    duration_seconds: float
    thread_id: str | None
    completed_usage: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]
    malformed_jsonl_lines: tuple[str, ...]
    stderr: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "marker": self.marker,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "duration_seconds": round(self.duration_seconds, 3),
            "thread_id": self.thread_id,
            "completed_usage": list(self.completed_usage),
            "events": list(self.events),
            "malformed_jsonl_lines": list(self.malformed_jsonl_lines),
            "stderr": self.stderr[-20_000:],
        }


class PromptRenderer:
    """Loads versioned prompts and substitutes only declared CI values."""

    def __init__(self, prompt_root: Path) -> None:
        self.prompt_root = prompt_root

    def generator(self, *, run_id: str, seed: int, max_scenarios: int) -> str:
        return self._template("generate-scenarios.md").substitute(
            RUN_ID=run_id,
            SEED=str(seed),
            MAX_SCENARIOS=str(max_scenarios),
        )

    def judge(self, evidence: dict[str, Any]) -> str:
        evidence_json = json.dumps(evidence, ensure_ascii=False, indent=2, sort_keys=True)
        return self._template("judge-evidence.md").substitute(EVIDENCE_JSON=evidence_json)

    def _template(self, filename: str) -> Template:
        path = self.prompt_root / filename
        return Template(path.read_text(encoding="utf-8"))


class CodexOrchestrator:
    """Runs the two Codex A phases and each explicitly proxied Codex B task."""

    def __init__(
        self,
        config: RuntimeConfig,
        commands: CommandRunner,
        prompts: PromptRenderer,
    ) -> None:
        self.config = config
        self.commands = commands
        self.prompts = prompts

    def generate_plan(self) -> ScenarioPlan:
        coordinator = self.config.runtime_root / "coordinator"
        output_path = coordinator / "scenario-plan.json"
        log_path = coordinator / "generator.jsonl"
        result = self._run_a(
            prompt=self.prompts.generator(
                run_id=self.config.run_id,
                seed=self.config.seed,
                max_scenarios=self.config.max_scenarios,
            ),
            schema=self.config.package_root / "schemas" / "scenario-plan.schema.json",
            output_path=output_path,
            model=self.config.generator_model,
        )
        log_path.write_text(result.stdout, encoding="utf-8")
        (coordinator / "generator.stderr.log").write_text(result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise OrchestrationError(
                f"Codex A scenario generation failed with exit code {result.returncode}: "
                f"{self._failure_detail(result)}"
            )
        value = self._read_json_object(output_path, "Codex A scenario plan")
        return ScenarioPlan.from_value(
            value,
            expected_run_id=self.config.run_id,
            expected_seed=self.config.seed,
            max_scenarios=self.config.max_scenarios,
        )

    def run_b(self, scenario: Scenario, workspace: Path, stack: TestStack) -> CodexBResult:
        marker = f"ABYSS_AGENT_E2E_{self.config.run_id}_{scenario.scenario_id}"
        prompt = "\n\n".join(
            (
                scenario.prompt,
                "The image attached to this Codex invocation is workspace/input.png.",
                (
                    "This exact audit marker identifies the run. Preserve it verbatim in your "
                    f"final response: {marker}"
                ),
                "Work only inside the current disposable workspace. Do not use network access.",
            )
        )
        arguments = [
            "codex",
            "exec",
            "--json",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--sandbox",
            "workspace-write",
            "--cd",
            str(workspace),
            "--image",
            str(workspace / "input.png"),
        ]
        if self.config.b_model:
            arguments.extend(("--model", self.config.b_model))
        # --image accepts one or more values, so an un-delimited positional prompt is
        # consumed as another image path by the Codex CLI. End option parsing and use
        # stdin explicitly; this also keeps generated prompts out of process listings.
        arguments.extend(("--", "-"))
        environment = self._direct_codex_environment()
        environment.update(
            {
                "HTTP_PROXY": stack.proxy_url,
                "HTTPS_PROXY": stack.proxy_url,
                "http_proxy": stack.proxy_url,
                "https_proxy": stack.proxy_url,
                "NO_PROXY": "localhost,127.0.0.1,::1",
                "no_proxy": "localhost,127.0.0.1,::1",
                "CODEX_CA_CERTIFICATE": str(stack.ca_certificate),
                "SSL_CERT_FILE": str(stack.ca_certificate),
            }
        )
        result = self.commands.run(
            arguments,
            cwd=workspace,
            env=environment,
            input_text=prompt,
            timeout=self.config.codex_timeout_seconds,
            check=False,
        )
        log_root = self.config.runtime_root / "logs" / "codex-b"
        log_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (log_root / f"{scenario.scenario_id}.jsonl").write_text(
            result.stdout,
            encoding="utf-8",
        )
        (log_root / f"{scenario.scenario_id}.stderr.log").write_text(
            result.stderr,
            encoding="utf-8",
        )
        return self._b_result(scenario.scenario_id, marker, result)

    def judge(self, evidence: dict[str, Any], scenario_ids: set[str]) -> Verdict:
        coordinator = self.config.runtime_root / "coordinator"
        output_path = coordinator / "verdict.json"
        result = self._run_a(
            prompt=self.prompts.judge(evidence),
            schema=self.config.package_root / "schemas" / "verdict.schema.json",
            output_path=output_path,
            model=self.config.judge_model,
        )
        (coordinator / "judge.jsonl").write_text(result.stdout, encoding="utf-8")
        (coordinator / "judge.stderr.log").write_text(result.stderr, encoding="utf-8")
        if result.returncode != 0:
            raise OrchestrationError(
                f"Codex A evidence judge failed with exit code {result.returncode}: "
                f"{self._failure_detail(result)}"
            )
        value = self._read_json_object(output_path, "Codex A verdict")
        return Verdict.from_value(
            value,
            expected_run_id=self.config.run_id,
            expected_seed=self.config.seed,
            scenario_ids=scenario_ids,
        )

    def _run_a(
        self,
        *,
        prompt: str,
        schema: Path,
        output_path: Path,
        model: str | None,
    ) -> CommandResult:
        arguments = [
            "codex",
            "exec",
            "--json",
            "--ephemeral",
            "--ignore-user-config",
            "--ignore-rules",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--cd",
            str(self.config.runtime_root / "coordinator"),
            "--output-schema",
            str(schema),
            "--output-last-message",
            str(output_path),
        ]
        if model:
            arguments.extend(("--model", model))
        # Generator and judge prompts contain audit evidence; keep them out of
        # world-readable process argument lists on the shared runner.
        arguments.extend(("--", "-"))
        return self.commands.run(
            arguments,
            cwd=self.config.runtime_root / "coordinator",
            env=self._direct_codex_environment(),
            input_text=prompt,
            timeout=self.config.codex_timeout_seconds,
            check=False,
        )

    @staticmethod
    def _read_json_object(path: Path, label: str) -> dict[str, Any]:
        if not path.is_file():
            raise OrchestrationError(f"{label} output file was not created")
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as error:
            raise ContractError(f"{label} is not valid JSON: {error}") from error
        if not isinstance(value, dict):
            raise ContractError(f"{label} must be a JSON object")
        return value

    @staticmethod
    def _failure_detail(result: CommandResult) -> str:
        messages: list[str] = []
        for line in result.stdout.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(event, dict):
                continue
            message: Any = None
            if event.get("type") == "error":
                message = event.get("message")
            elif event.get("type") == "turn.failed":
                error = event.get("error")
                if isinstance(error, dict):
                    message = error.get("message")
            if isinstance(message, str):
                normalized = " ".join(message.split())
                if normalized and normalized not in messages:
                    messages.append(normalized)
        if messages:
            return " | ".join(messages)[-4_000:]
        stderr = " ".join(result.stderr.split())
        return stderr[-4_000:] or "Codex emitted no structured error detail"

    @staticmethod
    def _direct_codex_environment() -> dict[str, str]:
        environment = os.environ.copy()
        for name in (
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "CODEX_CA_CERTIFICATE",
        ):
            environment.pop(name, None)
        environment["NO_PROXY"] = "localhost,127.0.0.1,::1"
        environment["no_proxy"] = "localhost,127.0.0.1,::1"
        return environment

    @staticmethod
    def _b_result(scenario_id: str, marker: str, result: CommandResult) -> CodexBResult:
        events: list[dict[str, Any]] = []
        malformed: list[str] = []
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                malformed.append(line[:2_000])
                continue
            if isinstance(value, dict):
                events.append(value)
            else:
                malformed.append(line[:2_000])
        thread_id = next(
            (
                event.get("thread_id")
                for event in events
                if event.get("type") == "thread.started"
                and isinstance(event.get("thread_id"), str)
            ),
            None,
        )
        completed_usage = tuple(
            event["usage"]
            for event in events
            if event.get("type") == "turn.completed" and isinstance(event.get("usage"), dict)
        )
        return CodexBResult(
            scenario_id=scenario_id,
            marker=marker,
            exit_code=result.returncode,
            timed_out=result.timed_out,
            duration_seconds=result.duration_seconds,
            thread_id=thread_id,
            completed_usage=completed_usage,
            events=tuple(events),
            malformed_jsonl_lines=tuple(malformed),
            stderr=result.stderr,
        )
