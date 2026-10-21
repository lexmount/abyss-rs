"""Runner setup and skip contracts for the hosted Agent E2E workflow."""

from __future__ import annotations

import unittest
from pathlib import Path


WORKFLOW = (
    Path(__file__).resolve().parents[2]
    / ".github"
    / "workflows"
    / "codex-agent-e2e.yml"
)


class AgentE2eWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_targets_hosted_runner_and_supports_audited_skip(self) -> None:
        self.assertIn("runs-on: ubuntu-latest", self.workflow)
        self.assertNotIn("self-hosted", self.workflow)
        self.assertIn("skip-agent-e2e", self.workflow)
        self.assertIn("Status: \\`SKIPPED\\`", self.workflow)

    def test_does_not_execute_fork_code_with_provider_credentials(self) -> None:
        self.assertIn("ABYSS_AGENT_E2E_FORK_SKIP", self.workflow)
        self.assertNotIn("pull_request_target", self.workflow)

    def test_sets_up_toolchains_and_pinned_client_before_preflight(self) -> None:
        self.assertIn("uses: ./.github/actions/setup-rust", self.workflow)
        self.assertIn("cache-shared-key: agent-e2e", self.workflow)
        self.assertIn("uses: actions/setup-node@v4", self.workflow)
        self.assertIn("@openai/codex@0.163.0", self.workflow)
        self.assertIn("uses: ./.github/actions/setup-codex-sandbox", self.workflow)
        self.assertIn('npm install --prefix "$tools_dir"', self.workflow)
        self.assertNotIn("npm install --global", self.workflow)
        self.assertLess(
            self.workflow.index("uses: ./.github/actions/setup-codex-sandbox"),
            self.workflow.index("- name: Validate runner prerequisites"),
        )


if __name__ == "__main__":
    unittest.main()
