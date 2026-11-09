"""Ensure live SDK tests cannot pass on provider errors or unrelated audit events."""

import contextlib
import copy
import os
import signal
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.blackbox_sdk_codex import (
    POLICY_REASON,
    allowed_exchange,
    child_environment,
    records,
    run_codex,
    validate_blocked_codex,
    validate_context,
)


class CodexSdkEvidenceTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "posix", "live Codex SDK runner uses POSIX process groups")
    def test_codex_exit_stops_background_directory_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executable = root / "codex"
            executable.write_text(
                f"#!{sys.executable}\n"
                "import pathlib, subprocess, sys, time\n"
                "child = subprocess.Popen([sys.executable, '-c', "
                "\"import os, pathlib, time; pathlib.Path('child.pid').write_text(str(os.getpid())); "
                "time.sleep(0.3); pathlib.Path('late-write').touch()\"], "
                "stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
                "while not pathlib.Path('child.pid').exists(): time.sleep(0.01)\n"
                "print('{\"type\":\"turn.completed\"}')\n"
            )
            executable.chmod(0o755)
            directory = root / "request"
            broker = SimpleNamespace(proxy_url="http://127.0.0.1:1", ca_file=root / "ca")
            try:
                with patch.dict(os.environ, {"PATH": f"{root}{os.pathsep}{os.environ['PATH']}"}):
                    result, events = run_codex(broker, directory, "marker", "model", "test-key")
                self.assertEqual(result.returncode, 0)
                self.assertEqual(events, [{"type": "turn.completed"}])
                time.sleep(0.5)
                self.assertFalse((directory / "late-write").exists())
            finally:
                pid_file = directory / "child.pid"
                if pid_file.exists():
                    with contextlib.suppress(ProcessLookupError):
                        os.kill(int(pid_file.read_text()), signal.SIGKILL)

    def test_provider_forbidden_is_not_plugin_rejection(self):
        with self.assertRaises(AssertionError):
            validate_blocked_codex(
                1,
                [
                    {
                        "type": "turn.failed",
                        "error": {"message": "403 provider refused access"},
                    }
                ],
                "",
            )
        validate_blocked_codex(
            1,
            [
                {
                    "type": "turn.failed",
                    "error": {"message": f"403 Forbidden: {POLICY_REASON}"},
                }
            ],
            "",
        )
        with self.assertRaises(AssertionError):
            validate_blocked_codex(
                0, [{"type": "turn.completed"}], f"403 {POLICY_REASON}"
            )

    def test_context_requires_agent_projection_and_redaction(self):
        call = {
            "kind": "inspection",
            "case": "block",
            "harness": "codex",
            "model": "test-model",
            "host": "api.openai.com",
            "server_name": "api.openai.com",
            "protocol": "openai_responses",
            "parsing_status": "parsed",
            "agent_has_marker": True,
            "json_has_marker": True,
            "credential_headers_absent": True,
            "source_process_absent": True,
            "allow": False,
        }
        self.assertEqual(validate_context([call], "block", "test-model"), 1)
        for field, value in (
            ("agent_has_marker", False),
            ("parsing_status", "unknown_protocol"),
            ("credential_headers_absent", False),
            ("server_name", None),
            ("allow", True),
        ):
            with self.subTest(field=field), self.assertRaises(AssertionError):
                validate_context([{**call, field: value}], "block", "test-model")
        with self.assertRaises(AssertionError):
            validate_context([], "block", "test-model")

    def test_completion_requires_a_correlated_real_response(self):
        request = {
            "kind": "event",
            "side": "request",
            "allow_marker": True,
            "response_id": "resp-1",
            "session_id": "session-1",
            "agent": "codex",
            "provider": "openai",
        }
        response = {**request, "side": "response", "token_usage": {"output_tokens": 3}}
        self.assertTrue(allowed_exchange([request, response]))
        for field, value in (
            ("response_id", "other"),
            ("response_id", None),
            ("session_id", "other"),
            ("allow_marker", False),
            ("token_usage", {"output_tokens": 0}),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(response)
                changed[field] = value
                self.assertFalse(allowed_exchange([request, changed]))
        self.assertFalse(allowed_exchange([response]))

    def test_evidence_reader_waits_for_complete_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "evidence.jsonl"
            self.assertEqual(records(path), [])
            path.write_text('{"kind":"ready"}\n{"kind":')
            self.assertEqual(records(path), [{"kind": "ready"}])

    def test_provider_key_is_not_inherited_by_broker_or_plugins(self):
        with patch.dict(
            os.environ,
            {
                "CODEX_API_KEY": "test-key",
                "OPENAI_API_KEY": "other-test-key",
                "HTTPS_PROXY": "http://test",
            },
        ):
            environment = child_environment()
        self.assertNotIn("CODEX_API_KEY", environment)
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("HTTPS_PROXY", environment)


if __name__ == "__main__":
    unittest.main()
