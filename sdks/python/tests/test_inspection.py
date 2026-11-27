"""Shared v1 action fixtures and callback input semantics."""

import json
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path

from abyss_sdk.plugin import AgentRequestContext, ModifyAction, RequestDecision

FIXTURES = Path(__file__).resolve().parents[3] / "specs/broker-plugin-protocol/v1/fixtures"


class InspectionTests(unittest.TestCase):
    def test_source_entry_preserves_script_and_module_shapes(self) -> None:
        for entry in [
            {"kind": "script", "path": "/opt/agent.js"},
            {"kind": "module", "runtime": "python", "name": "agent.main"},
        ]:
            value = json.loads((FIXTURES / "inspect-request.json").read_text())["context"]
            value["source_process"] = {
                "pid": 42,
                "pid_version": None,
                "name": None,
                "executable_path": None,
                "application_id": None,
                "entry_point": entry,
                "working_directory": None,
            }
            context = AgentRequestContext.from_dict(value)
            self.assertEqual(context.source_process.entry_point, entry)

    def test_actions_match_wire_contract_without_context_snapshot(self) -> None:
        expected = json.loads((FIXTURES / "inspect-response-modify.json").read_text())["decision"]
        decision = RequestDecision.modify(
            [
                ModifyAction.set_auth_token("fixture-token"),
                ModifyAction.set_auth_token("fixture-token", scheme="bearer"),
                ModifyAction.remove_auth_token(),
                ModifyAction.set_model("example-model"),
                ModifyAction.remove_model(),
            ]
        )
        self.assertEqual(decision.to_dict(), expected)
        self.assertNotIn("fixture-token", repr(decision))
        self.assertEqual(RequestDecision.allow().to_dict(), {"action": "allow"})
        self.assertEqual(
            RequestDecision.block("policy").to_dict(), {"action": "block", "reason": "policy"}
        )

    def test_context_exposes_token_without_including_it_in_repr(self) -> None:
        value = json.loads((FIXTURES / "inspect-request.json").read_text())["context"]
        value["auth_token"] = "private-credential"
        context = AgentRequestContext.from_dict(value)
        self.assertEqual(context.auth_token, "private-credential")
        self.assertNotIn("private-credential", repr(context))
        with self.assertRaises(FrozenInstanceError):
            context.auth_token = "changed"
