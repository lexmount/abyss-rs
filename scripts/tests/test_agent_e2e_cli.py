"""Black-box tests for the public Agent E2E validation commands."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_agent_e2e_contracts import RUN_ID, SEED, valid_plan, valid_verdict


REPO_ROOT = Path(__file__).resolve().parents[2]


class ValidationCliBlackBoxTests(unittest.TestCase):
    def test_validate_plan_command_accepts_valid_contract(self) -> None:
        result = self._run("validate-plan", valid_plan())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("valid scenario plan", result.stdout)

    def test_validate_plan_command_rejects_unsafe_contract(self) -> None:
        value = valid_plan()
        value["scenarios"][0]["files"][0]["path"] = "/etc/passwd"  # type: ignore[index]
        result = self._run("validate-plan", value)
        self.assertEqual(result.returncode, 2)
        self.assertIn("traverse", result.stderr)

    def test_validate_verdict_command_accepts_full_comparison(self) -> None:
        result = self._run("validate-verdict", valid_verdict())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("valid verdict", result.stdout)

    def _run(self, command: str, value: dict[str, object]) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            arguments = [
                sys.executable,
                "-m",
                "scripts.agent_e2e_ci",
                command,
                str(path),
                "--run-id",
                RUN_ID,
                "--seed",
                str(SEED),
            ]
            if command == "validate-verdict":
                arguments.extend(("--scenario-id", "inspect_colors"))
            return subprocess.run(
                arguments,
                cwd=REPO_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )


if __name__ == "__main__":
    unittest.main()
