"""Command-line entry point for the Codex-driven Agent E2E CI."""

from __future__ import annotations

import argparse
import json
import signal
import sys
import traceback
from pathlib import Path
from typing import Any

from .assets import FixtureWriter
from .codex import CodexOrchestrator, PromptRenderer
from .config import RuntimeConfig
from .evidence import BackendEvidenceCollector, EvidenceBuilder, ScenarioExecution, write_evidence
from .model import ContractError, ScenarioPlan, Verdict, VerdictStatus
from .preflight import RunnerPreflight
from .process import CommandRunner, LoopbackHttpClient, OrchestrationError
from .report import ReportWriter
from .stack import TestStack


class AgentE2eApplication:
    """Coordinates infrastructure and agent phases while preserving evidence."""

    def __init__(self, config: RuntimeConfig) -> None:
        self.config = config
        self.commands = CommandRunner()
        self.http = LoopbackHttpClient()
        self.report = ReportWriter(config)

    def run(self) -> int:
        stack = TestStack(self.config, self.commands, self.http)
        previous_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, self._termination_requested)
        try:
            preflight = RunnerPreflight(self.commands).run()
            stack.start()
            orchestrator = CodexOrchestrator(
                self.config,
                self.commands,
                PromptRenderer(self.config.package_root / "prompts"),
            )
            plan = orchestrator.generate_plan()
            workspace_root = self.config.runtime_root / "workspaces"
            workspace_root.mkdir(mode=0o700)
            writer = FixtureWriter()
            executions: list[ScenarioExecution] = []
            for scenario in plan.scenarios:
                workspace = workspace_root / scenario.scenario_id
                fixtures = writer.materialize(scenario, workspace)
                result = orchestrator.run_b(scenario, workspace, stack)
                executions.append(ScenarioExecution(result=result, fixtures=fixtures))

            backend = BackendEvidenceCollector(self.config, self.http, stack).collect(executions)
            evidence = EvidenceBuilder(self.config, stack).build(
                plan,
                executions,
                backend,
                preflight.codex_version,
            )
            write_evidence(
                self.config.runtime_root / "coordinator" / "evidence.json",
                evidence,
            )
            verdict = orchestrator.judge(
                evidence,
                {scenario.scenario_id for scenario in plan.scenarios},
            )
            self.report.success(
                evidence=evidence,
                verdict=verdict,
                preflight=preflight.as_dict(),
            )
            print(
                f"agent-e2e: {verdict.status.value} "
                f"(run={self.config.run_id}, seed={self.config.seed})"
            )
            print(f"agent-e2e: safe artifacts: {self.config.artifact_root}")
            return 0 if verdict.status is VerdictStatus.PASS else 1
        except (ContractError, OrchestrationError) as error:
            message = str(error)
            self.report.failure(message, write_artifact=stack.prepared)
            print(f"agent-e2e: {message}", file=sys.stderr)
            print(
                f"agent-e2e: runtime evidence retained at {self.config.runtime_root}",
                file=sys.stderr,
            )
            return 1
        except Exception as error:  # noqa: BLE001 - preserve artifacts for unexpected CI defects.
            message = f"unexpected {type(error).__name__}: {error}"
            self.report.failure(message, write_artifact=stack.prepared)
            traceback.print_exc()
            return 1
        finally:
            stack.stop()
            signal.signal(signal.SIGTERM, previous_sigterm)

    @staticmethod
    def _termination_requested(_signal_number: int, _frame: Any) -> None:
        raise OrchestrationError("CI termination requested; cleaning isolated resources")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Codex-driven Abyss Agent E2E CI")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("run", help="run the complete real-provider CI")
    subparsers.add_parser("preflight", help="check the runner without changing it")

    plan_parser = subparsers.add_parser(
        "validate-plan", help="validate a generated scenario plan"
    )
    plan_parser.add_argument("path", type=Path)
    plan_parser.add_argument("--run-id", required=True)
    plan_parser.add_argument("--seed", required=True, type=int)
    plan_parser.add_argument("--max-scenarios", type=int, default=3)

    verdict_parser = subparsers.add_parser(
        "validate-verdict", help="validate a semantic verdict"
    )
    verdict_parser.add_argument("path", type=Path)
    verdict_parser.add_argument("--run-id", required=True)
    verdict_parser.add_argument("--seed", required=True, type=int)
    verdict_parser.add_argument("--scenario-id", action="append", required=True)
    return parser


def main(arguments: list[str] | None = None) -> int:
    args = build_parser().parse_args(arguments)
    try:
        if args.command == "run":
            return AgentE2eApplication(RuntimeConfig.from_environment()).run()
        if args.command == "preflight":
            result = RunnerPreflight(CommandRunner()).run()
            print(json.dumps(result.as_dict(), sort_keys=True))
            return 0
        if args.command == "validate-plan":
            value = _read_json(args.path)
            ScenarioPlan.from_value(
                value,
                expected_run_id=args.run_id,
                expected_seed=args.seed,
                max_scenarios=args.max_scenarios,
            )
            print("valid scenario plan")
            return 0
        value = _read_json(args.path)
        Verdict.from_value(
            value,
            expected_run_id=args.run_id,
            expected_seed=args.seed,
            scenario_ids=set(args.scenario_id),
        )
        print("valid verdict")
        return 0
    except (ContractError, OrchestrationError, OSError, json.JSONDecodeError) as error:
        print(f"agent-e2e: {error}", file=sys.stderr)
        return 2


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ContractError("input must be a JSON object")
    return value
