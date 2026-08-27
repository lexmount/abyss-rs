"""Unit tests for Agent E2E contracts, fixtures, and evidence correlation."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from scripts.agent_e2e_ci.assets import PNG_SIGNATURE, FixtureWriter, PngEncoder
from scripts.agent_e2e_ci.codex import CodexOrchestrator, PromptRenderer
from scripts.agent_e2e_ci.config import RuntimeConfig
from scripts.agent_e2e_ci.evidence import BackendEvidenceCollector, EvidenceBuilder
from scripts.agent_e2e_ci.model import (
    ContractError,
    ImageSpec,
    Scenario,
    ScenarioPlan,
    Verdict,
    VerdictStatus,
)
from scripts.agent_e2e_ci.process import (
    CommandResult,
    CommandRunner,
    OrchestrationError,
    ProcessGroup,
)
from scripts.agent_e2e_ci.preflight import REQUIRED_CODEX_EXEC_OPTIONS, RunnerPreflight
from scripts.agent_e2e_ci.stack import TestStack


RUN_ID = "unit-42"
SEED = 42


def valid_scenario(scenario_id: str = "inspect_colors") -> dict[str, object]:
    return {
        "id": scenario_id,
        "title": "Inspect a randomized local fixture",
        "objective": "Read a token, inspect the image, edit a result, and verify it.",
        "prompt": "Inspect token.txt and input.png, then write result.txt and verify it.",
        "files": [
            {"path": "token.txt", "content": "opaque-unit-token\n"},
            {
                "path": "verify.py",
                "content": "from pathlib import Path\nassert Path('result.txt').is_file()\n",
            },
        ],
        "image": {
            "width": 32,
            "height": 40,
            "pattern": "quadrants",
            "palette": ["#112233", "#abcdef", "#ff0000", "#00ff00"],
        },
        "coverage_targets": {
            "tool_call": True,
            "tool_result": True,
            "image_input": True,
            "session_turn": True,
            "token_usage": True,
        },
        "rationale": "The answer depends on local tool output and attached pixels.",
    }


def valid_plan() -> dict[str, object]:
    return {"run_id": RUN_ID, "seed": SEED, "scenarios": [valid_scenario()]}


def valid_verdict() -> dict[str, object]:
    return {
        "status": "pass",
        "run_id": RUN_ID,
        "seed": SEED,
        "coverage": {
            "tool_call_observed": True,
            "matching_tool_result_observed": True,
            "image_transmitted": True,
            "session_turn_coherent": True,
            "token_usage_consistent": True,
            "run_isolated": True,
            "notes": "All requested evidence was present.",
        },
        "scenario_results": [
            {
                "id": "inspect_colors",
                "outcome": "match",
                "observed_behavior": "B read and edited local files.",
                "comparisons": [
                    {
                        "criterion": "tool activity",
                        "actual": "one completed command",
                        "backend": "matching call and result",
                        "outcome": "match",
                        "explanation": "The identifiers and payload hashes agree.",
                    }
                ],
                "issues": [],
            }
        ],
        "issues": [],
        "summary": "Abyss faithfully represented the observed run.",
        "recommended_action": "Allow the pull request check to pass.",
    }


def runtime_config(root: Path) -> RuntimeConfig:
    return RuntimeConfig(
        repo_root=Path(__file__).parents[2],
        runtime_root=root,
        run_id=RUN_ID,
        seed=SEED,
        max_scenarios=1,
        backend_image="test-backend",
        backend_platform="linux/amd64",
        postgres_image="postgres:16",
        generator_model=None,
        b_model=None,
        judge_model=None,
        codex_timeout_seconds=60,
        startup_timeout_seconds=30,
        event_timeout_seconds=10,
    )


class RecordingCommands:
    def __init__(self) -> None:
        self.arguments: list[str] | None = None
        self.options: dict[str, object] | None = None

    def run(self, arguments: list[str], **options: object) -> CommandResult:
        self.arguments = arguments
        self.options = options
        return CommandResult(
            args=tuple(arguments),
            returncode=0,
            stdout=json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
            stderr="",
            duration_seconds=0.1,
            timed_out=False,
        )


class ScenarioPlanTests(unittest.TestCase):
    def test_accepts_bounded_randomized_plan(self) -> None:
        plan = ScenarioPlan.from_value(
            valid_plan(),
            expected_run_id=RUN_ID,
            expected_seed=SEED,
        )
        self.assertEqual(plan.scenarios[0].scenario_id, "inspect_colors")
        self.assertEqual(plan.scenarios[0].image.pattern, "quadrants")

    def test_rejects_fixture_directory_traversal(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["files"][0]["path"] = "../native-token"  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "traverse"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_reserved_image_path(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["files"][0]["path"] = "input.png"  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "reserved"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_normalized_dot_component(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["files"][0]["path"] = "nested/./token.txt"  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "traverse"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_file_directory_prefix_conflict(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["files"] = [  # type: ignore[index]
            {"path": "output", "content": "file"},
            {"path": "output/nested.txt", "content": "nested"},
        ]
        with self.assertRaisesRegex(ContractError, "conflicts"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_plan_without_required_behavioral_targets(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["coverage_targets"]["tool_call"] = False  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "tool_call"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_unknown_coverage_target_after_schema_generation(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["coverage_targets"]["duplicate"] = True  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "keys do not match"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_oversized_prompt_after_schema_generation(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["prompt"] = "x" * (12 * 1024 + 1)  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "scenario prompt exceeds"):
            ScenarioPlan.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
            )

    def test_rejects_empty_required_strings_after_schema_generation(self) -> None:
        for field in ("title", "objective", "prompt", "rationale"):
            with self.subTest(field=field):
                value = valid_plan()
                value["scenarios"][0][field] = " \n"  # type: ignore[index]
                with self.assertRaisesRegex(ContractError, "non-empty"):
                    ScenarioPlan.from_value(
                        value,
                        expected_run_id=RUN_ID,
                        expected_seed=SEED,
                    )

        for field in ("path", "content"):
            with self.subTest(field=f"file.{field}"):
                value = valid_plan()
                value["scenarios"][0]["files"][0][field] = ""  # type: ignore[index]
                with self.assertRaisesRegex(ContractError, "non-empty"):
                    ScenarioPlan.from_value(
                        value,
                        expected_run_id=RUN_ID,
                        expected_seed=SEED,
                    )

    def test_rejects_identity_from_another_run(self) -> None:
        with self.assertRaisesRegex(ContractError, "run_id"):
            ScenarioPlan.from_value(
                valid_plan(),
                expected_run_id="another-run",
                expected_seed=SEED,
            )


class VerdictTests(unittest.TestCase):
    def test_accepts_structured_semantic_verdict(self) -> None:
        verdict = Verdict.from_value(
            valid_verdict(),
            expected_run_id=RUN_ID,
            expected_seed=SEED,
            scenario_ids={"inspect_colors"},
        )
        self.assertIs(verdict.status, VerdictStatus.PASS)

    def test_rejects_missing_scenario_comparisons(self) -> None:
        value = valid_verdict()
        value["scenario_results"][0]["comparisons"] = []  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "comparison"):
            Verdict.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
                scenario_ids={"inspect_colors"},
            )

    def test_rejects_result_for_unplanned_scenario(self) -> None:
        value = valid_verdict()
        value["scenario_results"][0]["id"] = "other"  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "scenario ids"):
            Verdict.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
                scenario_ids={"inspect_colors"},
            )

    def test_rejects_pass_that_declares_incomplete_coverage(self) -> None:
        value = valid_verdict()
        value["coverage"]["image_transmitted"] = False  # type: ignore[index]
        with self.assertRaisesRegex(ContractError, "passing verdict"):
            Verdict.from_value(
                value,
                expected_run_id=RUN_ID,
                expected_seed=SEED,
                scenario_ids={"inspect_colors"},
            )

    def test_rejects_empty_required_narrative_fields(self) -> None:
        for field in ("summary", "recommended_action"):
            with self.subTest(field=field):
                value = valid_verdict()
                value[field] = ""
                with self.assertRaisesRegex(ContractError, "non-empty"):
                    Verdict.from_value(
                        value,
                        expected_run_id=RUN_ID,
                        expected_seed=SEED,
                        scenario_ids={"inspect_colors"},
                    )

        for field in ("actual", "backend", "explanation"):
            with self.subTest(field=f"comparison.{field}"):
                value = valid_verdict()
                value["scenario_results"][0]["comparisons"][0][field] = ""  # type: ignore[index]
                with self.assertRaisesRegex(ContractError, "non-empty"):
                    Verdict.from_value(
                        value,
                        expected_run_id=RUN_ID,
                        expected_seed=SEED,
                        scenario_ids={"inspect_colors"},
                    )

        for location in ("coverage_notes", "observed_behavior", "issue_entry"):
            with self.subTest(field=location):
                value = valid_verdict()
                if location == "coverage_notes":
                    value["coverage"]["notes"] = ""  # type: ignore[index]
                elif location == "observed_behavior":
                    value["scenario_results"][0]["observed_behavior"] = ""  # type: ignore[index]
                else:
                    value["issues"] = [""]
                with self.assertRaisesRegex(ContractError, "non-empty"):
                    Verdict.from_value(
                        value,
                        expected_run_id=RUN_ID,
                        expected_seed=SEED,
                        scenario_ids={"inspect_colors"},
                    )


class FixtureTests(unittest.TestCase):
    def test_png_encoder_emits_valid_rgb_scanlines(self) -> None:
        spec = ImageSpec.from_value(valid_scenario()["image"])
        encoded = PngEncoder().encode(spec)
        self.assertTrue(encoded.startswith(PNG_SIGNATURE))
        width, height = struct.unpack(">II", encoded[16:24])
        self.assertEqual((width, height), (32, 40))

        offset = len(PNG_SIGNATURE)
        compressed = bytearray()
        while offset < len(encoded):
            length = struct.unpack(">I", encoded[offset : offset + 4])[0]
            kind = encoded[offset + 4 : offset + 8]
            payload = encoded[offset + 8 : offset + 8 + length]
            if kind == b"IDAT":
                compressed.extend(payload)
            offset += 12 + length
        scanlines = zlib.decompress(compressed)
        self.assertEqual(len(scanlines), 40 * (1 + 32 * 3))

    def test_fixture_manifest_matches_materialized_bytes(self) -> None:
        scenario = Scenario.from_value(valid_scenario())
        with tempfile.TemporaryDirectory() as temporary:
            workspace = Path(temporary) / "scenario"
            manifest = FixtureWriter().materialize(scenario, workspace)
            image = (workspace / "input.png").read_bytes()
            self.assertEqual(manifest.image["sha256"], hashlib.sha256(image).hexdigest())
            self.assertEqual(manifest.image["byte_size"], len(image))
            self.assertEqual((workspace / "token.txt").read_text(), "opaque-unit-token\n")


class CodexObservationTests(unittest.TestCase):
    def test_run_b_delivers_prompt_through_stdin_after_variadic_image_option(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "input.png").write_bytes(b"png")
            ca_certificate = root / "ca.pem"
            ca_certificate.write_text("test-ca", encoding="utf-8")
            config = runtime_config(root)
            commands = RecordingCommands()
            orchestrator = CodexOrchestrator(
                config,
                commands,  # type: ignore[arg-type]
                PromptRenderer(config.package_root / "prompts"),
            )
            scenario = Scenario.from_value(valid_scenario())

            orchestrator.run_b(
                scenario,
                workspace,
                SimpleNamespace(
                    proxy_url="http://127.0.0.1:43210",
                    ca_certificate=ca_certificate,
                ),  # type: ignore[arg-type]
            )

            self.assertIsNotNone(commands.arguments)
            self.assertIsNotNone(commands.options)
            assert commands.arguments is not None
            assert commands.options is not None
            self.assertEqual(commands.arguments[-2:], ["--", "-"])
            self.assertNotIn(scenario.prompt, commands.arguments)
            input_text = commands.options["input_text"]
            self.assertIsInstance(input_text, str)
            self.assertIn(scenario.prompt, input_text)
            self.assertIn(f"ABYSS_AGENT_E2E_{RUN_ID}_{scenario.scenario_id}", input_text)

    def test_run_a_keeps_evidence_prompt_out_of_process_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "coordinator").mkdir()
            config = runtime_config(root)
            commands = RecordingCommands()
            orchestrator = CodexOrchestrator(
                config,
                commands,  # type: ignore[arg-type]
                PromptRenderer(config.package_root / "prompts"),
            )
            prompt = "sensitive evidence bundle"

            orchestrator._run_a(
                prompt=prompt,
                schema=config.package_root / "schemas" / "verdict.schema.json",
                output_path=root / "coordinator" / "verdict.json",
                model=None,
            )

            self.assertIsNotNone(commands.arguments)
            self.assertIsNotNone(commands.options)
            assert commands.arguments is not None
            assert commands.options is not None
            self.assertEqual(commands.arguments[-2:], ["--", "-"])
            self.assertNotIn(prompt, commands.arguments)
            self.assertEqual(commands.options["input_text"], prompt)

    def test_parses_thread_usage_and_malformed_jsonl_without_hiding_it(self) -> None:
        stdout = "\n".join(
            (
                json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
                json.dumps(
                    {
                        "type": "item.completed",
                        "item": {"type": "command_execution", "exit_code": 0},
                    }
                ),
                "not-json",
                json.dumps(
                    {"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 2}}
                ),
            )
        )
        result = CommandResult(
            args=("codex",),
            returncode=0,
            stdout=stdout,
            stderr="",
            duration_seconds=1.25,
            timed_out=False,
        )
        observation = CodexOrchestrator._b_result("case", "MARKER", result)
        self.assertEqual(observation.thread_id, "thread-1")
        self.assertEqual(observation.completed_usage[0]["input_tokens"], 10)
        self.assertEqual(observation.malformed_jsonl_lines, ("not-json",))

    def test_backend_correlation_includes_entire_marker_session(self) -> None:
        result = CodexOrchestrator._b_result(
            "case",
            "MARKER",
            CommandResult(
                args=("codex",),
                returncode=0,
                stdout=json.dumps({"type": "thread.started", "thread_id": "thread-1"}),
                stderr="",
                duration_seconds=0.1,
                timed_out=False,
            ),
        )
        events = [
            {"event_id": "1", "session_id": "thread-1", "text": "MARKER prompt"},
            {"event_id": "2", "session_id": "thread-1", "text": "tool output"},
            {"event_id": "3", "session_id": "thread-2", "text": "unrelated"},
        ]
        selected = BackendEvidenceCollector._events_for(result, events)
        self.assertEqual([event["event_id"] for event in selected], ["1", "2"])

    def test_compacts_large_evidence_with_a_reproducible_hash(self) -> None:
        value = "雪" * 5_000
        compacted = EvidenceBuilder._compact({"output": value})
        record = compacted["output"]
        self.assertEqual(record["evidence_encoding"], "truncated_utf8")
        self.assertEqual(record["byte_size"], len(value.encode("utf-8")))
        self.assertEqual(record["sha256"], hashlib.sha256(value.encode("utf-8")).hexdigest())

    def test_failure_detail_reports_only_structured_errors(self) -> None:
        result = CommandResult(
            args=("codex",),
            returncode=1,
            stdout="\n".join(
                (
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {"text": "sensitive partial model output"},
                        }
                    ),
                    json.dumps({"type": "error", "message": "invalid output schema"}),
                    json.dumps(
                        {
                            "type": "turn.failed",
                            "error": {"message": "invalid output schema"},
                        }
                    ),
                )
            ),
            stderr="Reading additional input from stdin...",
            duration_seconds=0.1,
            timed_out=False,
        )
        detail = CodexOrchestrator._failure_detail(result)
        self.assertEqual(detail, "invalid output schema")
        self.assertNotIn("sensitive", detail)


class StructuredOutputSchemaTests(unittest.TestCase):
    UNSUPPORTED_KEYWORDS = {
        "allOf",
        "contains",
        "dependentRequired",
        "dependentSchemas",
        "else",
        "if",
        "maxContains",
        "maxLength",
        "minContains",
        "minLength",
        "not",
        "oneOf",
        "patternProperties",
        "propertyNames",
        "then",
        "unevaluatedProperties",
        "uniqueItems",
    }

    def test_codex_output_schemas_use_the_supported_strict_subset(self) -> None:
        schema_root = Path(__file__).parents[1] / "agent_e2e_ci" / "schemas"
        for path in sorted(schema_root.glob("*.schema.json")):
            with self.subTest(schema=path.name):
                schema = json.loads(path.read_text(encoding="utf-8"))
                self._assert_supported(schema, path.name)

    def _assert_supported(self, value: object, location: str) -> None:
        if isinstance(value, list):
            for index, item in enumerate(value):
                self._assert_supported(item, f"{location}[{index}]")
            return
        if not isinstance(value, dict):
            return
        unsupported = self.UNSUPPORTED_KEYWORDS.intersection(value)
        self.assertFalse(unsupported, f"{location} uses unsupported keywords: {unsupported}")
        if value.get("type") == "object":
            properties = value.get("properties")
            self.assertIsInstance(properties, dict, f"{location} has no properties object")
            self.assertIs(value.get("additionalProperties"), False, location)
            self.assertEqual(set(value.get("required", [])), set(properties), location)
        if value.get("type") == "string":
            if "enum" in value:
                self.assertNotIn("", value["enum"], location)
            else:
                pattern = value.get("pattern")
                self.assertIsInstance(pattern, str, f"{location} accepts an empty string")
                self.assertIsNone(re.search(pattern, ""), location)
        for key, item in value.items():
            self._assert_supported(item, f"{location}.{key}")


class StackSafetyTests(unittest.TestCase):
    def test_backend_receives_only_the_native_token_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = runtime_config(Path(temporary))
            commands = RecordingCommands()
            stack = TestStack(
                config,
                commands,  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
            )
            raw_token = stack.native_token
            token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
            try:
                stack.http = SimpleNamespace(wait_until=lambda *args, **kwargs: None)  # type: ignore[assignment]
                stack._start_backend()
            finally:
                stack.backend_started = False
                stack._release_port_reservations()

            self.assertIsNotNone(commands.arguments)
            self.assertIsNotNone(commands.options)
            assert commands.arguments is not None
            assert commands.options is not None
            arguments = " ".join(commands.arguments)
            self.assertIn(f"ABYSS_BACKEND_API_TOKEN_SHA256={token_hash}", arguments)
            self.assertNotIn(raw_token, arguments)
            self.assertIn("ABYSS_BACKEND_BLACKBOX_ALLOW_NON_LOOPBACK=true", arguments)

    def test_broker_stop_does_not_propagate_timeout_after_force_stop(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            stack = TestStack(
                runtime_config(Path(temporary)),
                RecordingCommands(),  # type: ignore[arg-type]
                SimpleNamespace(),  # type: ignore[arg-type]
            )
            process = Mock()
            process.pid = 42
            process.poll.return_value = None
            process.wait.side_effect = [
                subprocess.TimeoutExpired("broker", 15),
                subprocess.TimeoutExpired("broker", 5),
                subprocess.TimeoutExpired("broker", 5),
            ]
            stack.broker_process = process
            try:
                with (
                    patch.object(ProcessGroup, "request_stop") as request_stop,
                    patch.object(ProcessGroup, "force_stop") as force_stop,
                ):
                    stack._stop_broker()
            finally:
                stack._release_port_reservations()

            self.assertIsNone(stack.broker_process)
            self.assertEqual(process.wait.call_count, 3)
            request_stop.assert_called_once_with(process)
            force_stop.assert_called_once_with(process)


class CommandRunnerTests(unittest.TestCase):
    def test_timeout_returns_explicit_observation(self) -> None:
        result = CommandRunner().run(
            [sys.executable, "-c", "import time; time.sleep(10)"],
            timeout=1,
            check=False,
        )
        self.assertTrue(result.timed_out)
        self.assertEqual(result.returncode, 124)


class RunnerPreflightTests(unittest.TestCase):
    def test_reports_missing_docker_and_codex_login_together(self) -> None:
        class FakeCommands:
            def run(self, arguments: list[str], **_kwargs: object) -> CommandResult:
                if arguments[:3] == ["codex", "login", "status"]:
                    return self._result(arguments, returncode=1)
                if arguments[:3] == ["codex", "exec", "--help"]:
                    return self._result(
                        arguments,
                        stdout=" ".join(REQUIRED_CODEX_EXEC_OPTIONS),
                    )
                raise AssertionError(f"unexpected command: {arguments}")

            @staticmethod
            def _result(
                arguments: list[str],
                *,
                returncode: int = 0,
                stdout: str = "",
            ) -> CommandResult:
                return CommandResult(
                    args=tuple(arguments),
                    returncode=returncode,
                    stdout=stdout,
                    stderr="",
                    duration_seconds=0.1,
                    timed_out=False,
                )

        def command_path(command: str) -> str | None:
            return None if command == "docker" else f"/usr/bin/{command}"

        with (
            patch("scripts.agent_e2e_ci.preflight.platform.system", return_value="Linux"),
            patch("scripts.agent_e2e_ci.preflight.shutil.which", side_effect=command_path),
            self.assertRaises(OrchestrationError) as raised,
        ):
            RunnerPreflight(FakeCommands()).run()  # type: ignore[arg-type]
        self.assertIn("missing required commands: docker", str(raised.exception))
        self.assertIn("not authenticated", str(raised.exception))


class PromptTests(unittest.TestCase):
    def test_generator_prompt_records_reproducible_identity(self) -> None:
        prompt_root = Path(__file__).parents[1] / "agent_e2e_ci" / "prompts"
        prompt = PromptRenderer(prompt_root).generator(
            run_id=RUN_ID,
            seed=SEED,
            max_scenarios=2,
        )
        self.assertIn(RUN_ID, prompt)
        self.assertIn("random seed: `42`", prompt)
        self.assertIn("between one and `2`", prompt)


if __name__ == "__main__":
    unittest.main()
