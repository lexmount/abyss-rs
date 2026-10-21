"""Matrix contracts, native trace accounting and real CLI black-box checks."""

from __future__ import annotations

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.agent_e2e_ci.model import ContractError
from scripts.agent_e2e_ci.codex import CodexOrchestrator
from scripts.agent_e2e_ci.preflight import RunnerPreflight, REQUIRED_CODEX_EXEC_OPTIONS
from scripts.agent_e2e_ci.process import CommandRunner, OrchestrationError
from scripts.agent_matrix_ci.catalog import HARNESS_PROTOCOLS, MatrixCatalog
from scripts.agent_matrix_ci.cli import MatrixApplication, summarize
from scripts.agent_matrix_ci.clients import HeadlessClient
from scripts.agent_matrix_ci.transcript import Transcript
from scripts.agent_matrix_ci.verification import MatrixVerifier, SecretRedactor


ROOT = Path(__file__).resolve().parents[2]


def jsonl(*events: dict) -> str:
    return "\n".join(json.dumps(e) for e in events)


class CatalogTests(unittest.TestCase):
    def test_resource_names_fit_dns_and_certificate_limits(self):
        cases = MatrixCatalog().cases()
        identifiers = [c.resource_id("long_run_name_" * 20) for c in cases]
        self.assertEqual(len(set(identifiers)), len(cases))
        for identifier in identifiers:
            self.assertLessEqual(len("abyss-agent-e2e-postgres-" + identifier), 63)
            self.assertLessEqual(len("Abyss Agent E2E " + identifier), 64)
            self.assertRegex(identifier, r"^matrix-[a-f0-9]{24}$")
        self.assertNotEqual(
            cases[0].resource_id("attempt1"), cases[0].resource_id("attempt2")
        )

    def test_complete_supported_cross_product(self):
        cases = MatrixCatalog().cases()
        expected_secrets = {
            "openai": "CODEX_API_KEY",
            "anthropic": "CLAUDE_CODE_API_KEY",
            "deepseek": "ABYSS_E2E_DEEPSEEK_API_KEY",
            "glm": "ABYSS_E2E_GLM_API_KEY",
            "kimi": "ABYSS_E2E_KIMI_API_KEY",
            "qwen": "ABYSS_E2E_QWEN_API_KEY",
        }
        self.assertEqual(len(cases), 32)
        self.assertEqual(len({c.id for c in cases}), len(cases))
        self.assertEqual(len({(c.harness, c.provider) for c in cases}), 16)
        for c in cases:
            self.assertIn(c.protocol, HARNESS_PROTOCOLS[c.harness])
            self.assertNotIn(c.harness, ("claude-desktop", "dsh-tui", "dsh-web"))
            self.assertEqual(c.secret, expected_secrets[c.provider])
        self.assertEqual(
            {c.provider for c in cases if c.harness == "codex"},
            {"openai", "deepseek", "glm", "kimi", "qwen"},
        )
        self.assertEqual(
            {c.provider for c in cases if c.harness == "claude-code"},
            {"anthropic", "deepseek", "glm", "kimi", "qwen"},
        )

    def test_model_and_regional_endpoint_overrides(self):
        catalog = MatrixCatalog(
            '{"qwen":{"messages":["qwen-test-a","qwen-test-b"]}}',
            '{"qwen":{"messages":"https://coding.dashscope.aliyuncs.com/apps/anthropic/"}}',
        )
        cases = catalog.cases(provider="qwen", protocol="messages")
        self.assertEqual(len(cases), 4)
        self.assertEqual(cases[0].event_provider, "coding.dashscope.aliyuncs.com")
        self.assertFalse(cases[0].base_url.endswith("/"))
        self.assertEqual(len(catalog.cases(model="qwen-test-a")), 2)

    def test_invalid_or_empty_selections_never_succeed(self):
        for kwargs in (
            {"harness": "typo"},
            {"harness": "codex", "provider": "anthropic"},
            {"harness": "claude-code", "provider": "openai"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ContractError):
                MatrixCatalog().cases(**kwargs)
        for raw in (
            "[]",
            '{"typo":{}}',
            '{"openai":{"messages":["x"]}}',
            '{"openai":{"responses":[]}}',
            '{"openai":{"responses":["a","a"]}}',
            '{"openai":{"responses":["a\nb"]}}',
        ):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                MatrixCatalog(models=raw)

    def test_credentials_and_non_https_endpoints_rejected(self):
        for url in (
            "http://example.com",
            "https://user:secret@example.com",
            "https://example.com?k=secret",
            "https://example.com/#secret",
            "https://exam ple.com",
        ):
            with self.subTest(url=url), self.assertRaises(ContractError):
                MatrixCatalog(endpoints=json.dumps({"openai": {"responses": url}}))

    def test_gateways_keep_hostname(self):
        case = MatrixCatalog(
            endpoints='{"anthropic":{"messages":"https://relay.example/api"}}'
        ).cases(provider="anthropic")[0]
        self.assertEqual(case.event_provider, "relay.example")


class ClientTests(unittest.TestCase):
    def test_runtime_relay_routes_both_anthropic_clients_only(self):
        endpoint = "https://private-relay.example/anthropic/"
        with tempfile.TemporaryDirectory() as root:
            workspace = Path(root) / "workspace"
            workspace.mkdir()
            stack = SimpleNamespace(
                proxy_url="http://127.0.0.1:1234", ca_certificate=Path(root) / "ca.pem"
            )
            for case in MatrixCatalog().cases():
                app = MatrixApplication(case, None, "fixture-key", endpoint=endpoint)
                with self.subTest(case=case.id):
                    self.assertEqual(app.planned_case, case)
                    if case.provider != "anthropic":
                        self.assertEqual(app.case, case)
                        self.assertFalse(app.endpoint_secrets)
                        continue
                    self.assertEqual(app.case.event_provider, "private-relay.example")
                    self.assertEqual(app.case.base_url, endpoint.rstrip("/"))
                    client = HeadlessClient(app.case, CommandRunner())
                    _, env = client.invocation(workspace, stack, "fixture-key")
                    if case.harness == "claude-code":
                        self.assertEqual(env["ANTHROPIC_BASE_URL"], app.case.base_url)
                    else:
                        self.assertEqual(
                            client.dsh_patch()[-1]["config"]["baseURL"],
                            app.case.base_url,
                        )

    def test_runtime_relay_errors_are_redacted_and_keep_plan_identity(self):
        endpoint = "https://private-relay.example/anthropic"
        case = MatrixCatalog().cases(provider="anthropic")[0]
        with tempfile.TemporaryDirectory() as root:
            runtime = Path(root) / "runtime"
            config = SimpleNamespace(
                run_id="fixture",
                runtime_root=runtime,
                artifact_root=runtime / "artifacts",
            )
            app = MatrixApplication(case, config, "fixture-key", endpoint=endpoint)
            with (
                patch("scripts.agent_matrix_ci.cli.TestStack") as stack,
                patch.object(
                    HeadlessClient,
                    "preflight",
                    side_effect=OrchestrationError(
                        f"failed {endpoint}: private-relay.example fixture-key"
                    ),
                ),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                stack.return_value.native_token = "fixture-native-token"
                self.assertEqual(app.run(), 1)
                self.assertEqual(
                    stack.call_args.kwargs["interception_hosts"],
                    ("private-relay.example",),
                )
                report = json.loads((config.artifact_root / "result.json").read_text())
                self.assertEqual(report["case"], case.as_dict())
                self.assertEqual(report["endpoint_source"], "CLAUDE_CODE_BASE_URL")
                self.assertEqual(summarize([case.as_dict()], config.artifact_root), 1)
                for secret in (endpoint, "private-relay.example", "fixture-key"):
                    self.assertNotIn(secret, json.dumps(report))
                    self.assertNotIn(secret, output.getvalue())

    def test_existing_codex_workflow_accepts_key_without_login(self):
        class Commands:
            def __init__(self):
                self.calls = []

            def run(self, args, **_kwargs):
                self.calls.append(args)
                return SimpleNamespace(
                    returncode=0,
                    stdout=" ".join(REQUIRED_CODEX_EXEC_OPTIONS),
                    stderr="",
                )

        commands = Commands()
        with (
            patch.dict(os.environ, {"CODEX_API_KEY": "fixture-key"}),
            patch(
                "scripts.agent_e2e_ci.preflight.platform.system", return_value="Linux"
            ),
            patch(
                "scripts.agent_e2e_ci.preflight.shutil.which", return_value="/bin/tool"
            ),
        ):
            RunnerPreflight(commands).run()
            args = CodexOrchestrator._api_provider_arguments()
            self.assertNotIn("fixture-key", json.dumps(args))
            self.assertIn("CODEX_API_KEY", json.dumps(args))
        self.assertNotIn(["codex", "login", "status"], commands.calls)
        with patch.dict(os.environ, {"CODEX_API_KEY": ""}):
            with self.assertRaises(OrchestrationError):
                CodexOrchestrator._api_provider_arguments()

    def test_every_invocation_uses_only_selected_key_and_temp_configuration(self):
        with (
            tempfile.TemporaryDirectory() as root,
            patch.dict(
                os.environ,
                {
                    "ANTHROPIC_API_KEY": "unrelated-key",
                    "ALL_PROXY": "unrelated-proxy",
                    "NODE_OPTIONS": "untrusted-loader",
                },
            ),
        ):
            workspace = Path(root) / "workspace"
            workspace.mkdir()
            stack = SimpleNamespace(
                proxy_url="http://127.0.0.1:1234", ca_certificate=Path(root) / "ca.pem"
            )
            for case in MatrixCatalog().cases():
                with self.subTest(case=case.id):
                    args, env = HeadlessClient(case, CommandRunner()).invocation(
                        workspace, stack, "fixture-key"
                    )
                    self.assertNotIn("fixture-key", json.dumps(args))
                    self.assertNotIn("unrelated-key", json.dumps(env))
                    self.assertNotIn("NODE_OPTIONS", env)
                    self.assertEqual(env["HTTPS_PROXY"], stack.proxy_url)
                    key_name = (
                        "ANTHROPIC_API_KEY"
                        if case.harness == "claude-code"
                        else "MATRIX_PROVIDER_KEY"
                    )
                    self.assertEqual(env[key_name], "fixture-key")
                    if case.harness == "deepseek-harness":
                        self.assertNotIn(
                            "fixture-key", (Path(root) / "dsh-patch.json").read_text()
                        )
                        self.assertIn(str(Path(root) / "dsh-home"), env.values())

    def test_native_messages_and_pi_routes_are_explicit(self):
        for case in MatrixCatalog().cases(harness="deepseek-harness"):
            entries = HeadlessClient(case, CommandRunner()).dsh_patch()
            settings = entries[-1]
            if case.protocol == "messages":
                self.assertEqual(settings["id"], "llm-deepseek")
                self.assertEqual(settings["config"]["baseURL"], case.base_url)
            else:
                provider = settings["config"]["providers"]["matrix"]
                self.assertEqual(
                    provider["api"],
                    "openai-responses"
                    if case.protocol == "responses"
                    else "openai-completions",
                )


class TranscriptTests(unittest.TestCase):
    def test_codex_retains_unavailable_fields(self):
        trace = Transcript.parse(
            "codex",
            jsonl(
                {"type": "thread.started", "thread_id": "s"},
                {
                    "type": "item.completed",
                    "item": {"type": "command_execution", "aggregated_output": "nonce"},
                },
                {
                    "type": "item.completed",
                    "item": {"type": "agent_message", "text": "answer"},
                },
                {
                    "type": "turn.completed",
                    "usage": {
                        "input_tokens": 10,
                        "cached_input_tokens": 3,
                        "output_tokens": 2,
                    },
                },
            ),
        )
        self.assertTrue(trace.completed)
        self.assertNotIn("cache_write_input_tokens", trace.usage[0])
        self.assertIn("nonce", trace.tool_outputs[0])

    def test_claude_uses_corrected_stream_usage_not_provisional_snapshot(self):
        trace = Transcript.parse(
            "claude-code",
            jsonl(
                {
                    "type": "stream_event",
                    "event": {
                        "type": "message_start",
                        "message": {
                            "usage": {
                                "input_tokens": 100,
                                "output_tokens": 1,
                                "cache_read_input_tokens": 0,
                            }
                        },
                    },
                },
                {"type": "assistant", "message": {"usage": {"input_tokens": 100}}},
                {
                    "type": "stream_event",
                    "event": {
                        "type": "message_delta",
                        "usage": {
                            "input_tokens": 5,
                            "cache_read_input_tokens": 90,
                            "output_tokens": 7,
                        },
                    },
                },
                {"type": "stream_event", "event": {"type": "message_stop"}},
                {
                    "type": "result",
                    "is_error": False,
                    "session_id": "s",
                    "result": "answer",
                },
            ),
        )
        self.assertEqual(
            trace.usage,
            [{"input_tokens": 95, "output_tokens": 7, "cached_input_tokens": 90}],
        )
        self.assertTrue(trace.completed)

    def test_messages_compatible_details_do_not_double_count_input(self):
        usage = Transcript._messages_usage(
            {
                "input_tokens": 100,
                "output_tokens": 7,
                "input_tokens_details": {"cached_tokens": 90},
            }
        )
        self.assertEqual(usage["input_tokens"], 100)
        self.assertEqual(usage["cached_input_tokens"], 90)

    def test_dsh_sums_steps_and_matches_tool_ids(self):
        trace = Transcript.parse(
            "deepseek-harness",
            jsonl(
                {"type": "session", "sessionId": "s"},
                {
                    "type": "tool_result",
                    "callId": "call-a",
                    "status": "completed",
                    "result": "nonce",
                },
                {
                    "type": "status",
                    "phase": "step_end",
                    "usage": {
                        "inputTokens": 5,
                        "cacheReadTokens": 90,
                        "outputTokens": 7,
                    },
                },
                {"type": "final", "text": "answer"},
            ),
        )
        self.assertEqual(trace.usage[0]["input_tokens"], 95)
        self.assertEqual(trace.call_ids, {"call-a"})
        self.assertNotIn("cache_write_input_tokens", trace.usage[0])

    def test_malformed_trace_and_counters_fail(self):
        for output in (
            "not-json",
            "[]",
            '{"type":"turn.completed","usage":{"input_tokens":-1}}',
        ):
            with self.subTest(output=output), self.assertRaises(ContractError):
                Transcript.parse("codex", output)


class VerificationTests(unittest.TestCase):
    def setUp(self):
        self.case = MatrixCatalog().cases(
            harness="codex", provider="openai", model="gpt-5"
        )[0]
        self.native = Transcript(
            final_text="marker nonce",
            session_id="session",
            tool_outputs=["nonce"],
            usage=[{"input_tokens": 10, "output_tokens": 6, "cached_input_tokens": 4}],
            completed=True,
        )
        self.events = []
        for i in range(4):
            self.events.append(
                {
                    "event_id": str(i),
                    "event_type": "response" if i % 2 else "request",
                    "response_id": f"response-{i // 2}",
                    "agent_name": "codex",
                    "llm_provider": "openai",
                    "llm_model": "gpt-5",
                    "session_id": "session",
                    "input_tokens": 3 if i % 2 == 0 else 0,
                    "cache_read_tokens": 2 if i % 2 == 0 else 0,
                    "output_tokens": 3 if i % 2 else 0,
                    "metadata": {
                        "conversation": {"completeness": "complete", "messages": []}
                    },
                }
            )
        self.events[1]["metadata"]["content_segments"] = [
            {"type": "tool_call", "call_id": "call", "name": "read"}
        ]
        self.events[2]["metadata"]["content_segments"] = [
            {"type": "tool_result", "call_id": "call", "output": "nonce"}
        ]
        self.events[3]["metadata"]["conversation"]["messages"] = [
            {"role": "assistant", "text": "marker nonce"}
        ]

    def verify(self, events=None, **overrides):
        args = dict(
            marker="marker",
            nonce="nonce",
            exit_code=0,
            timed_out=False,
            healthy=True,
            spool_empty=True,
        )
        args.update(overrides)
        return MatrixVerifier.verify(
            self.case, self.native, self.events if events is None else events, **args
        )

    def test_complete_trace_passes_exact_accounting(self):
        result = self.verify()
        self.assertEqual(result["status"], "pass", result["failed_checks"])
        self.assertEqual(
            result["usage"]["difference"],
            {"input_tokens": 0, "output_tokens": 0, "cached_input_tokens": 0},
        )

    def test_dsh_responses_compound_ids_compare_wire_component(self):
        self.case = MatrixCatalog().cases(
            harness="deepseek-harness",
            provider="openai",
            protocol="responses",
            model="gpt-5",
        )[0]
        for event in self.events:
            event["agent_name"] = "deepseek-harness"
        self.native.call_ids = {"call|fc-item"}
        self.assertEqual(self.verify()["status"], "pass")
        self.native.call_ids = {"wrong-call|fc-item"}
        self.assertIn("native_tool_ids", self.verify()["failed_checks"])

    def test_observation_mutations_cannot_pass(self):
        for key, value in (
            ("input_tokens", 100),
            ("agent_name", "other"),
            ("llm_model", "wrong"),
            ("session_id", "wrong"),
            ("llm_provider", "wrong"),
        ):
            events = copy.deepcopy(self.events)
            events[0][key] = value
            with self.subTest(key=key):
                self.assertEqual(self.verify(events)["status"], "fail")
        self.assertEqual(self.verify([])["status"], "fail")
        self.assertEqual(self.verify(self.events + [self.events[0]])["status"], "fail")

    def test_broken_tool_roundtrip_and_partial_capture_fail(self):
        events = copy.deepcopy(self.events)
        events[2]["metadata"]["content_segments"][0]["call_id"] = "wrong"
        self.assertIn("tool_roundtrip", self.verify(events)["failed_checks"])
        events[0]["metadata"]["conversation"]["completeness"] = "partial"
        self.assertIn("complete_conversation", self.verify(events)["failed_checks"])

    def test_failures_are_not_skips(self):
        for options in (
            {"exit_code": 1},
            {"timed_out": True},
            {"healthy": False},
            {"spool_empty": False},
        ):
            self.assertEqual(self.verify(**options)["status"], "fail")
        self.native.completed = False
        self.assertEqual(self.verify()["status"], "fail")


class MatrixCliBlackboxTests(unittest.TestCase):
    def command(self, *args, env=None):
        environment = HeadlessClient.base_environment()
        environment.update(env or {})
        return subprocess.run(
            [sys.executable, "-m", "scripts.agent_matrix_ci", *args],
            cwd=ROOT,
            env=environment,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def test_plan_and_invalid_filter(self):
        result = self.command(
            "plan",
            "--harness",
            "claude-code",
            env={"CLAUDE_CODE_BASE_URL": "https://private-relay.example/anthropic"},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(json.loads(result.stdout)["include"]), 6)
        self.assertNotIn("private-relay.example", result.stdout + result.stderr)
        self.assertNotEqual(self.command("plan", "--provider", "typo").returncode, 0)

    def test_missing_secret_creates_failure_artifact_without_tools_or_login(self):
        cases = [
            MatrixCatalog().cases()[0],
            MatrixCatalog().cases(provider="anthropic")[0],
        ]
        for case in cases:
            with self.subTest(case=case.id), tempfile.TemporaryDirectory() as root:
                runtime = Path(root) / "run"
                result = self.command(
                    "run",
                    "--case",
                    case.id,
                    env={
                        "ABYSS_AGENT_E2E_RUNTIME_ROOT": str(runtime),
                        "CLAUDE_CODE_BASE_URL": "https://api.anthropic.com",
                    },
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                report = json.loads((runtime / "artifacts/result.json").read_text())
                self.assertEqual(report["status"], "error")
                self.assertEqual(report["case"], case.as_dict())
                self.assertIn(case.secret, report["error"])
                self.assertFalse((runtime / "ca").exists())

    def test_aggregate_requires_all_planned_cells(self):
        cases = [
            c.as_dict()
            for c in MatrixCatalog().cases(harness="claude-code", provider="anthropic")
        ]
        with tempfile.TemporaryDirectory() as root:
            env = {"ABYSS_E2E_EXPECTED_MATRIX": json.dumps({"include": cases})}
            self.assertEqual(
                self.command("summarize", "--results", root, env=env).returncode, 1
            )
            result_path = Path(root) / "result.json"
            for status, exit_code in (
                ("pass", 0),
                ("fail", 1),
                ("error", 1),
                ("skipped", 1),
            ):
                result_path.write_text(json.dumps({"case": cases[0], "status": status}))
                self.assertEqual(
                    self.command("summarize", "--results", root, env=env).returncode,
                    exit_code,
                )

    def test_workflow_limits_credentials_and_keeps_other_cells_running(self):
        workflow = (ROOT / ".github/workflows/agent-model-matrix.yml").read_text()
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("secrets[matrix.secret]", workflow)
        self.assertIn(
            "matrix.provider == 'anthropic' && secrets.CLAUDE_CODE_BASE_URL", workflow
        )
        self.assertIn("if: needs.plan.outputs.enabled == 'true'", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("login", workflow)
        self.assertIn("max-parallel: 8", workflow)
        self.assertNotIn("self-hosted", workflow)
        self.assertIn("uses: ./.github/actions/setup-rust", workflow)
        self.assertIn("cache-shared-key: agent-e2e", workflow)
        self.assertIn("uses: ./.github/actions/setup-codex-sandbox", workflow)
        self.assertLess(
            workflow.index("uses: ./.github/actions/setup-codex-sandbox"),
            workflow.index("- name: Run real headless client through Abyss"),
        )
        self.assertIn('npm install --prefix "$tools_dir"', workflow)
        self.assertNotIn("npm install -g", workflow)
        self.assertIn("@openai/codex@0.163.0", workflow)
        self.assertIn("@anthropic-ai/claude-code@2.1.206", workflow)
        self.assertIn("@deepseek-ai/dsh@0.2.0-rc.2", workflow)

    def test_secret_redaction_in_nested_artifacts(self):
        result = SecretRedactor("api-secret", "broker-secret").document(
            {"errors": ["failed api-secret", {"header": "broker-secret"}]}
        )
        self.assertNotIn("api-secret", result)
        self.assertNotIn("broker-secret", result)
        self.assertEqual(json.loads(result)["errors"][0], "failed [REDACTED]")
        escaped = 'secret"with\\escapes'
        self.assertEqual(
            json.loads(SecretRedactor(escaped).document({"key": escaped})),
            {"key": "[REDACTED]"},
        )


if __name__ == "__main__":
    unittest.main()
