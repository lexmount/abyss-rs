"""Check the credential scope of the Codex DeepSeek example plugin."""

import json
import unittest
from dataclasses import replace
from pathlib import Path

from abyss_sdk.plugin import AgentRequestContext, ModifyAction, RequestHarness
from examples.codex_deepseek_auth import CodexDeepSeekAuth

FIXTURES = Path(__file__).resolve().parents[3] / "specs/broker-plugin-protocol/v1/fixtures"


class CodexDeepSeekAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        value = json.loads((FIXTURES / "inspect-request.json").read_text())["context"]
        self.context = replace(
            AgentRequestContext.from_dict(value),
            destination_host="api.deepseek.com",
            server_name="api.deepseek.com",
            harness=RequestHarness("codex", None, None, None, None, None),
            auth_token="client-placeholder",
            auth_token_writable=True,
        )
        self.plugin = CodexDeepSeekAuth("local-test-secret")

    def test_replaces_only_auth_and_does_not_log_credentials(self) -> None:
        with self.assertLogs(level="INFO") as logs:
            decision = self.plugin.inspect(self.context)
        self.assertEqual(decision.action, "modify")
        self.assertEqual(decision.actions, (ModifyAction.set_auth_token("local-test-secret"),))
        self.assertEqual(self.context.auth_token, "client-placeholder")
        for secret in ("local-test-secret", "client-placeholder"):
            self.assertNotIn(secret, "\n".join(logs.output))

    def test_other_destinations_and_harnesses_are_unchanged(self) -> None:
        for context in (
            replace(self.context, server_name="api.openai.com", destination_host="api.openai.com"),
            replace(self.context, server_name="api.deepseek.com.evil.test"),
            replace(self.context, harness=None),
            replace(self.context, harness=replace(self.context.harness, id="claude-code")),
        ):
            with self.subTest(host=context.server_name, harness=context.harness):
                self.assertEqual(self.plugin.inspect(context).action, "allow")

    def test_handshake_can_be_modified_without_a_parsed_model(self) -> None:
        handshake = replace(self.context, agent=None, parsing_status="unknown_protocol")
        self.assertEqual(self.plugin.inspect(handshake).action, "modify")

    def test_websocket_messages_keep_the_handshake_credential(self) -> None:
        message = replace(self.context, websocket=True, sequence=1, auth_token_writable=False)
        self.assertEqual(self.plugin.inspect(message).action, "allow")

    def test_destination_host_is_used_without_tls_server_name(self) -> None:
        context = replace(self.context, server_name=None)
        self.assertEqual(self.plugin.inspect(context).action, "modify")
