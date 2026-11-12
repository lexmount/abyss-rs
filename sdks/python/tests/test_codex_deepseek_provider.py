"""The provider example returns all three edits only for eligible Codex requests."""

import json
import unittest
from dataclasses import replace
from pathlib import Path

from abyss_sdk.plugin import AgentRequestContext, ModifyAction, RequestHarness
from examples.codex_deepseek_provider import CodexDeepSeekProvider

FIXTURES = Path(__file__).resolve().parents[3] / "specs/broker-plugin-protocol/v1/fixtures"


class CodexDeepSeekProviderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.context = AgentRequestContext.from_dict(
            json.loads((FIXTURES / "inspect-request.json").read_text())["context"]
        )
        self.context = replace(
            self.context, harness=RequestHarness("codex", None, None, None, None, None)
        )
        self.plugin = CodexDeepSeekProvider("provider-secret")

    def test_switches_url_credential_and_model_together(self) -> None:
        with self.assertLogs(level="INFO") as logs:
            decision = self.plugin.inspect(self.context)
        self.assertEqual(
            decision.actions,
            (
                ModifyAction.set_provider("https://api.deepseek.com"),
                ModifyAction.set_auth_token("provider-secret"),
                ModifyAction.set_model("deepseek-flash"),
            ),
        )
        self.assertNotIn("provider-secret", "\n".join(logs.output))
        self.assertEqual(self.context.provider, "https://api.openai.com/v1")

    def test_keeps_other_providers_harnesses_and_established_connections(self) -> None:
        for context in (
            replace(self.context, provider="https://api.openai.com.evil.test/v1"),
            replace(self.context, provider="https://api.deepseek.com"),
            replace(self.context, harness=None),
            replace(self.context, model_writable=False),
            replace(self.context, provider_writable=False),
            replace(self.context, auth_token_writable=False),
        ):
            self.assertEqual(self.plugin.inspect(context).action, "allow")


if __name__ == "__main__":
    unittest.main()
