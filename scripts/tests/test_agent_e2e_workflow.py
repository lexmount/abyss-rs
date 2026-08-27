"""Static safety assertions for the self-hosted Agent E2E workflow."""

from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "codex-agent-e2e.yml"


class AgentE2eWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_targets_dedicated_runner_and_supports_audited_skip(self) -> None:
        self.assertIn("runs-on: [self-hosted, abyss, Linux, X64]", self.workflow)
        self.assertIn("skip-agent-e2e", self.workflow)
        self.assertIn("Status: \\`SKIPPED\\`", self.workflow)

    def test_does_not_execute_fork_code_with_runner_login(self) -> None:
        self.assertIn("ABYSS_AGENT_E2E_FORK_SKIP", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)

    def test_does_not_install_runner_toolchains(self) -> None:
        for forbidden in ("setup-node", "setup-rust", "npm install", "apt-get", "rustup"):
            self.assertNotIn(forbidden, self.workflow)


if __name__ == "__main__":
    unittest.main()
