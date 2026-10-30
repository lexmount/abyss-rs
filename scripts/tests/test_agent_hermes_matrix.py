"""Hermes isolation, native transcript, resume and CI installation contracts."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.agent_e2e_ci.model import ContractError
from scripts.agent_e2e_ci.process import CommandResult, CommandRunner
from scripts.agent_matrix_ci.catalog import MatrixCatalog
from scripts.agent_matrix_ci.cli import MatrixApplication
from scripts.agent_matrix_ci.clients import HeadlessClient
from scripts.agent_matrix_ci.hermes import HermesClient
from scripts.agent_matrix_ci.transcript import Transcript
from scripts.agent_matrix_ci.verification import MatrixVerifier

ROOT = Path(__file__).resolve().parents[2]


def completed(session="native-session", text="marker nonce", **extra):
    return {
        "type": "result",
        "session_id": session,
        "exit_code": 0,
        "text": text,
        "tokens": {"input": 6, "output": 2, "cache_read": 3, "cache_write": 1},
        **extra,
    }


def jsonl(*events):
    return "\n".join(json.dumps(e) for e in events)


class HermesTranscriptTests(unittest.TestCase):
    def test_three_resumed_processes_keep_uncached_and_cache_usage_distinct(self):
        trace = Transcript.parse(
            "hermes",
            jsonl(
                {"type": "system", "subtype": "init", "session_id": ""},
                {"type": "tool_result", "tool_call_id": "call", "output": "nonce"},
                completed(),
                completed(),
                completed(),
            ),
        )
        self.assertTrue(trace.completed)
        self.assertEqual(trace.session_id, "native-session")
        self.assertEqual(trace.call_ids, {"call"})
        self.assertEqual([turn["tool_results"] for turn in trace.turns], [1, 0, 0])
        self.assertEqual(
            trace.usage,
            [
                {
                    "input_tokens": 10,
                    "output_tokens": 2,
                    "cached_input_tokens": 3,
                    "cache_write_input_tokens": 1,
                }
            ]
            * 3,
        )
        self.assertNotIn("reasoning_output_tokens", trace.usage[0])

    def test_missing_native_usage_is_not_fabricated(self):
        trace = Transcript.parse("hermes", jsonl(completed(tokens={})))
        self.assertEqual(trace.usage, [{}])
        for bad in (-1, True, "10"):
            with self.subTest(bad=bad), self.assertRaises(ContractError):
                Transcript.parse("hermes", jsonl(completed(tokens={"input": bad})))

    def test_error_and_changed_resume_session_are_retained(self):
        for event in (
            completed(session="different"),
            completed(exit_code=1, error="failed"),
        ):
            with self.subTest(event=event):
                trace = Transcript.parse("hermes", jsonl(completed(), event))
                self.assertTrue(trace.errors)


class HermesClientTests(unittest.TestCase):
    def test_real_plugin_and_explicit_protocol_installed_in_isolated_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            ca = root / "ca.pem"
            ca.write_text("fixture-ca\n")
            stack = SimpleNamespace(
                ca_certificate=ca, proxy_url="http://127.0.0.1:1234"
            )
            for case in MatrixCatalog().cases(harness="hermes"):
                args, env = HeadlessClient(case, CommandRunner()).invocation(
                    workspace, stack, "test-key"
                )
                home = Path(env["HERMES_HOME"])
                config = json.loads((home / "config.yaml").read_text())
                provider = config["providers"]["matrix"]
                self.assertEqual(
                    provider["api_mode"], HermesClient.API_MODES[case.protocol]
                )
                self.assertEqual(provider["base_url"], case.base_url)
                self.assertEqual(provider["key_env"], "MATRIX_PROVIDER_KEY")
                self.assertNotIn("test-key", json.dumps(config) + json.dumps(args))
                self.assertEqual(env["MATRIX_PROVIDER_KEY"], "test-key")
                self.assertEqual(env["HERMES_DISABLE_LAZY_INSTALLS"], "1")
                self.assertIn("fixture-ca", Path(provider["ssl_ca_cert"]).read_text())
                self.assertEqual(
                    (home / "plugins/abyss/__init__.py").read_bytes(),
                    (ROOT / "integrations/hermes/abyss/__init__.py").read_bytes(),
                )
                self.assertEqual(
                    args[args.index("--reasoning") + 1],
                    "none"
                    if case.provider == "openai" and case.protocol == "chat"
                    else "low",
                )

    def test_resume_uses_native_identity_and_removes_fixture_after_first_turn(self):
        case = MatrixCatalog().cases(harness="hermes")[0]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "probe.txt").write_text("nonce")
            app = MatrixApplication(
                case, SimpleNamespace(codex_timeout_seconds=60), "key"
            )
            client = HeadlessClient(case, app.commands)
            calls = []

            def run(args, **kwargs):
                calls.append((args, kwargs))
                self.assertEqual((workspace / "probe.txt").exists(), len(calls) == 1)
                return CommandResult(tuple(args), 0, jsonl(completed()), "", 1.0, False)

            with (
                patch.object(
                    client, "invocation", return_value=(["hermes", "chat"], {})
                ),
                patch.object(app.commands, "run", side_effect=run),
            ):
                result = app._run_client(client, workspace, None, "first prompt")
            self.assertEqual(len(calls), 3)
            self.assertNotIn("--resume", calls[0][0])
            for args, kwargs in calls[1:]:
                self.assertEqual(args[args.index("--resume") + 1], "native-session")
                self.assertIn("--no-restore-cwd", args)
                self.assertNotIn("nonce", args[args.index("-q") + 1])
                self.assertNotIn("input_text", kwargs)
            self.assertEqual(len(Transcript.parse("hermes", result.stdout).turns), 3)
            self.assertEqual((root / "probe-first-turn.txt").read_text(), "nonce")

    def test_failed_first_turn_stops_without_resuming(self):
        case = MatrixCatalog().cases(harness="hermes")[0]
        app = MatrixApplication(case, SimpleNamespace(codex_timeout_seconds=60), "key")
        client = HeadlessClient(case, app.commands)
        failed = CommandResult(
            ("hermes",), 1, jsonl(completed(exit_code=1)), "failed", 1, False
        )
        with (
            patch.object(client, "invocation", return_value=(["hermes"], {})),
            patch.object(app.commands, "run", return_value=failed) as run,
        ):
            result = app._run_client(client, Path("unused"), None, "query")
        self.assertEqual(run.call_count, 1)
        self.assertEqual(result.returncode, 1)

    def test_install_is_pinned_locked_and_separate_from_npm_clients(self):
        revision = (ROOT / "scripts/ci/hermes-revision.txt").read_text().strip()
        self.assertRegex(revision, r"^[a-f0-9]{40}$")
        script = (ROOT / "scripts/ci/install_hermes.sh").read_text()
        for expected in (
            "https://github.com/NousResearch/hermes-agent.git",
            '"$revision"',
            "--locked",
            "--python 3.14",
            "--extra anthropic",
            "GITHUB_PATH",
        ):
            self.assertIn(expected, script)
        workflow = (ROOT / ".github/workflows/agent-model-matrix.yml").read_text()
        self.assertIn("if: matrix.harness != 'hermes'", workflow)
        self.assertIn("if: matrix.harness == 'hermes'", workflow)
        self.assertIn("bash scripts/ci/install_hermes.sh", workflow)


class HermesVerificationTests(unittest.TestCase):
    def setUp(self):
        self.case = MatrixCatalog().cases(
            harness="hermes", provider="openai", protocol="chat"
        )[0]
        self.native = Transcript.parse(
            "hermes",
            jsonl(
                {"type": "tool_result", "tool_call_id": "call", "output": "nonce"},
                completed(),
                completed(),
                completed(),
            ),
        )
        self.events = []
        for turn in (1, 2, 3):
            for side in ("request", "response"):
                request = side == "request"
                self.events.append(
                    {
                        "event_id": f"{turn}-{side}",
                        "response_id": f"resp-{turn}",
                        "event_type": side,
                        "agent_name": "hermes",
                        "llm_provider": "openai",
                        "llm_model": self.case.model,
                        "session_id": "native-session",
                        "location": {"turn": turn},
                        "input_tokens": 6 if request else 0,
                        "output_tokens": 0 if request else 2,
                        "cache_read_tokens": 3 if request else 0,
                        "cache_write_tokens": 1 if request else 0,
                        "conversation": {
                            "completeness": "complete",
                            "entries": [
                                {
                                    "role": "user" if request else "assistant",
                                    "text": "query" if request else "marker nonce",
                                }
                            ],
                        },
                        "metadata": {},
                    }
                )
        self.events[1]["conversation"]["entries"].append(
            {"role": "tool_call", "text": "{}", "call_id": "call", "name": "read_file"}
        )
        self.events[2]["conversation"]["entries"].append(
            {"role": "tool_result", "text": "nonce", "call_id": "call"}
        )

    def verify(self, events=None):
        return MatrixVerifier.verify(
            self.case,
            self.native,
            self.events if events is None else events,
            marker="marker",
            nonce="nonce",
            exit_code=0,
            timed_out=False,
            healthy=True,
            spool_empty=True,
        )

    def test_three_turns_and_exact_usage_pass(self):
        report = self.verify()
        self.assertEqual(report["status"], "pass", report["failed_checks"])
        self.assertEqual(report["usage"]["native"]["input_tokens"], 30)

    def test_merged_turns_and_history_only_answers_fail(self):
        for mutate in ("merge", "missing_answer", "wrong_session", "usage"):
            events = copy.deepcopy(self.events)
            if mutate == "merge":
                for event in events:
                    event["location"]["turn"] = 1
            elif mutate == "missing_answer":
                events[-1]["conversation"]["entries"][0]["text"] = "missing"
            elif mutate == "wrong_session":
                events[-1]["session_id"] = "other"
            else:
                events[-1]["output_tokens"] += 1
            with self.subTest(mutate=mutate):
                self.assertEqual(self.verify(events)["status"], "fail")

    def test_missing_native_turn_and_tool_based_recall_fail(self):
        self.native.turns.pop()
        self.assertIn("three_native_user_turns", self.verify()["failed_checks"])
        self.native.turns.append(dict(self.native.turns[-1], tool_results=1))
        self.assertIn("resumed_memory_without_tools", self.verify()["failed_checks"])


if __name__ == "__main__":
    unittest.main()
