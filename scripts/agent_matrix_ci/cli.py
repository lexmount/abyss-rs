"""Plan, run and aggregate isolated real-provider matrix checks."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import signal
import sys
import time
from dataclasses import replace
from pathlib import Path

from scripts.agent_e2e_ci.config import RuntimeConfig
from scripts.agent_e2e_ci.model import ContractError
from scripts.agent_e2e_ci.process import (
    CommandRunner,
    CommandResult,
    LoopbackHttpClient,
    OrchestrationError,
)
from scripts.agent_e2e_ci.stack import TestStack

from .catalog import MatrixCase, MatrixCatalog
from .clients import HeadlessClient
from .transcript import Transcript
from .verification import MatrixVerifier, SecretRedactor


class MatrixApplication:
    def __init__(
        self, case: MatrixCase, config: RuntimeConfig, key: str, *, endpoint: str = ""
    ) -> None:
        self.case, self.config, self.key = case, config, key
        self.planned_case = case
        self.endpoint_secrets: tuple[str, ...] = ()
        if endpoint and case.provider == "anthropic":
            MatrixCatalog.validate_url(endpoint)
            self.case = replace(case, base_url=endpoint.rstrip("/"))
            self.endpoint_secrets = (endpoint, self.case.base_url, self.case.host)
        self.commands = CommandRunner()
        self.http = LoopbackHttpClient()

    def run(self) -> int:
        # Parent operations must never inherit the provider key. The caller
        # removes it from os.environ and passes it only to the native client.
        stack = TestStack(
            self.config,
            self.commands,
            self.http,
            harness_id=self.case.harness,
            interception_hosts=(self.case.host,),
        )
        redactor = SecretRedactor(self.key, stack.native_token, *self.endpoint_secrets)
        report = {"status": "error", "case": self.case.as_dict()}
        old_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, self._terminate)
        try:
            if not self.key.strip():
                raise ContractError(
                    f"required GitHub secret is not configured: {self.case.secret}"
                )
            client = HeadlessClient(self.case, self.commands)
            versions = client.preflight()
            print(f"matrix: starting {self.case.id}", flush=True)
            stack.start()
            redactor = SecretRedactor(
                self.key, stack.native_token, stack.broker_token, *self.endpoint_secrets
            )
            workspace = self.config.runtime_root / "workspace"
            workspace.mkdir(mode=0o700)
            nonce = "OBSERVED_" + secrets.token_hex(16)
            marker = "ABYSS_MATRIX_" + secrets.token_hex(12)
            (workspace / "probe.txt").write_text(
                f"Verification code: {nonce}\n", encoding="utf-8"
            )
            prompt = (
                "Read probe.txt in the current working directory using your file read tool "
                "(or cat via your shell tool). Then report its exact Verification code and "
                f"this audit marker: {marker}. You must actually use the tool. "
                "Do not edit any files, use the network, or read anything outside this workspace."
            )
            result = self._run_client(client, workspace, stack, prompt)
            report["process"] = {
                "exit_code": result.returncode,
                "timed_out": result.timed_out,
                "stdout": result.stdout[-16000:],
                "stderr": result.stderr[-8000:],
            }
            native = Transcript.parse(self.case.harness, result.stdout)
            events = self._collect(stack)
            health = stack.health_snapshot()
            healthy = (
                health.get("backend", {}).get("status") == "ok"
                and health.get("delivery_plugin", {}).get("running") is True
                and not any(
                    "error" in health.get(name, {}) for name in ("broker", "proxy")
                )
            )
            report = MatrixVerifier.verify(
                self.case,
                native,
                events,
                marker=marker,
                nonce=nonce,
                exit_code=result.returncode,
                timed_out=result.timed_out,
                healthy=healthy,
                spool_empty=not stack.spool_path.exists()
                or stack.spool_path.stat().st_size == 0,
            )
            report.update(
                versions=versions,
                duration_seconds=result.duration_seconds,
                stderr=result.stderr[-8000:],
                infrastructure=health,
            )
        except (ContractError, OrchestrationError, OSError, ValueError) as error:
            report.update(status="error", error=str(error))
        except Exception as error:
            report.update(status="error", error=f"{type(error).__name__}: {error}")
        finally:
            try:
                stack.stop()
            except Exception as error:
                report.update(status="error", cleanup_error=str(error))
            signal.signal(signal.SIGTERM, old_handler)
        report["run_id"] = self.config.run_id
        if self.endpoint_secrets:
            report["endpoint_source"] = "CLAUDE_CODE_BASE_URL"
        # Also write preflight/missing-secret failures. Never overwrite an
        # existing runtime: the CLI rejects it before constructing a stack.
        self.config.artifact_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self.config.artifact_root / "result.json"
        artifact = json.loads(redactor.document(report))
        # Restore only the public plan identity after redaction, including when
        # the secret endpoint happens to equal the public default. Runtime
        # provider assertions above still use the effective relay hostname.
        artifact["case"] = self.planned_case.as_dict()
        path.write_text(
            json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        summary = f"{self.case.id}: {report['status'].upper()}"
        if report.get("failed_checks"):
            summary += " (" + ", ".join(report["failed_checks"]) + ")"
        if report.get("error"):
            summary += ": " + redactor.text(report["error"])
        print(summary, flush=True)
        return 0 if report["status"] == "pass" else 1

    def _run_client(
        self, client: HeadlessClient, workspace: Path, stack: TestStack, prompt: str
    ) -> CommandResult:
        args, environment = client.invocation(workspace, stack, self.key)
        if self.case.harness != "hermes":
            positional = self.case.harness == "deepseek-harness"
            return self.commands.run(
                args + ([prompt] if positional else []),
                cwd=workspace,
                env=environment,
                input_text=None if positional else prompt,
                timeout=self.config.codex_timeout_seconds,
                check=False,
            )
        prompts = [prompt]
        prompts.extend(
            f"User turn {turn}: From our conversation, repeat the exact Verification code "
            "and audit marker from the first turn. Do not use any tools or read files. "
            "Reply with both strings only."
            for turn in (2, 3)
        )
        results = []
        session = None
        for turn, query in enumerate(prompts, 1):
            command = args + ["-q", query]
            if session:
                command += ["--resume", session, "--no-restore-cwd"]
            result = self.commands.run(
                command,
                cwd=workspace,
                env=environment,
                timeout=self.config.codex_timeout_seconds,
                check=False,
            )
            results.append(result)
            native = Transcript.parse("hermes", result.stdout)
            if (
                result.returncode
                or result.timed_out
                or not native.completed
                or not native.session_id
            ):
                break
            if session and native.session_id != session:
                break  # Aggregate validation also rejects the changed identity.
            session = native.session_id
            if turn == 1:
                # The subsequent answers must use resumed history, not re-read
                # the first-turn fixture. Preserve it outside the test workspace.
                (workspace / "probe.txt").rename(
                    workspace.parent / "probe-first-turn.txt"
                )
        return CommandResult(
            args=results[0].args,
            returncode=next((r.returncode for r in results if r.returncode), 0),
            stdout="\n".join(r.stdout for r in results),
            stderr="\n".join(r.stderr for r in results),
            duration_seconds=sum(r.duration_seconds for r in results),
            timed_out=any(r.timed_out for r in results),
        )

    def _collect(self, stack: TestStack) -> list[dict]:
        deadline = time.monotonic() + self.config.event_timeout_seconds
        previous, stable = None, 0
        events = []
        while time.monotonic() < deadline:
            response = self.http.json(
                f"{stack.backend_base_url}/v1/agent-usage/events?limit=1000&locate=true",
                bearer=stack.native_token,
            )
            events = response.get("events")
            if not isinstance(events, list) or not all(
                isinstance(e, dict) for e in events
            ):
                raise OrchestrationError("invalid Backend events response")
            if len(events) >= 1000:
                raise OrchestrationError("matrix evidence reached pagination limit")
            identity = sorted(str(e.get("event_id")) for e in events)
            stable = stable + 1 if events and identity == previous else 0
            spool_empty = (
                not stack.spool_path.exists() or stack.spool_path.stat().st_size == 0
            )
            if stable >= 5 and spool_empty:
                return events
            previous = identity
            time.sleep(1)
        return events

    @staticmethod
    def _terminate(_signum, _frame) -> None:
        raise OrchestrationError("matrix job terminated; cleaning isolated resources")


def summarize(expected: list[dict], directory: Path) -> int:
    reports = {}
    for path in directory.rglob("result.json"):
        value = json.loads(path.read_text(encoding="utf-8"))
        identity = value["case"]["id"]
        if identity in reports:
            raise ContractError("duplicate matrix result: " + identity)
        reports[identity] = value
    expected_ids = {case["id"] for case in expected}
    if not expected or len(expected_ids) != len(expected):
        raise ContractError("expected matrix must be nonempty and contain unique cells")
    if set(reports) - expected_ids:
        raise ContractError("unexpected matrix results")
    lines = [
        "## Headless harness × model matrix",
        "",
        "| Harness | Provider | Model | Protocol | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    passed = True
    for case in expected:
        report = reports.get(case["id"], {})
        if report and report.get("case") != case:
            raise ContractError(
                "matrix result configuration differs from plan: " + case["id"]
            )
        status = report.get("status", "MISSING")
        passed &= status == "pass"
        lines.append(
            f"| {case['harness']} | {case['provider']} | {case['model']} | {case['protocol']} | {status} |"
        )
    summary = "\n".join(lines) + "\n"
    print(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(path).open("a", encoding="utf-8") as handle:
            handle.write(summary)
    return 0 if passed else 1


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("plan", "run", "summarize"))
    for name in ("harness", "provider", "protocol", "model", "case"):
        parser.add_argument("--" + name, default="")
    parser.add_argument("--results", type=Path)
    args = parser.parse_args(arguments)
    try:
        catalog = MatrixCatalog(
            os.environ.get("ABYSS_E2E_MODELS", ""),
            os.environ.get("ABYSS_E2E_ENDPOINTS", ""),
        )
        cases = catalog.cases(
            harness=args.harness,
            provider=args.provider,
            protocol=args.protocol,
            model=args.model,
        )
        if args.command == "plan":
            print(
                json.dumps(
                    {"include": [case.as_dict() for case in cases]},
                    separators=(",", ":"),
                )
            )
            return 0
        if args.command == "summarize":
            if not args.results:
                raise ContractError("--results is required")
            expected = json.loads(os.environ["ABYSS_E2E_EXPECTED_MATRIX"])["include"]
            return summarize(expected, args.results)
        selected = [case for case in cases if case.id == args.case]
        if len(selected) != 1:
            raise ContractError("--case must identify exactly one planned matrix case")
        key = os.environ.pop("ABYSS_MATRIX_API_KEY", "")
        endpoint = os.environ.pop("CLAUDE_CODE_BASE_URL", "")
        config = RuntimeConfig.from_environment()
        # Add the cell hash to Docker names even when a local caller only supplies
        # a workflow run ID. GitHub also gives each cell a distinct runtime path.
        config = replace(config, run_id=selected[0].resource_id(config.run_id))
        if config.runtime_root.exists():
            raise ContractError("runtime root already exists; use a fresh path")
        return MatrixApplication(selected[0], config, key, endpoint=endpoint).run()
    except (ContractError, OrchestrationError, OSError, ValueError, KeyError) as error:
        print(f"matrix: {error}", file=sys.stderr)
        return 2
