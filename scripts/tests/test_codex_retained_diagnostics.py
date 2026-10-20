"""Verify the temporary collector exposes errors without conversation content."""

import importlib.util
import json
import unittest
from pathlib import Path


spec = importlib.util.spec_from_file_location(
    "diagnostics", Path(__file__).resolve().parents[1] / "codex_retained_diagnostics.py"
)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
Diagnostics = module.RetainedDiagnostics


class DiagnosticTests(unittest.TestCase):
    def test_errors_exclude_conversation_and_credentials(self):
        stdout = "\n".join(json.dumps(event) for event in [
            {"type": "item.completed", "item": {"text": "PRIVATE_PROMPT"}},
            {"type": "error", "message": '429 Bearer SECRET_TOKEN sk-secret123 api_key="OTHER_SECRET"'},
        ])
        stderr = r'body: "{\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"TPM limit 100, requested 200\"}}" x-request-id: "req-123" authorization: "SECRET_HEADER"'
        result = Diagnostics.error_details(stdout, stderr)
        encoded = json.dumps(result)
        for secret in ("PRIVATE_PROMPT", "SECRET_TOKEN", "sk-secret123", "OTHER_SECRET", "SECRET_HEADER"):
            self.assertNotIn(secret, encoded)
        self.assertIn("rate_limit_exceeded", encoded)
        self.assertIn("TPM limit 100", encoded)
        self.assertIn("req-123", encoded)

    def test_url_credentials_and_query_are_removed(self):
        result = Diagnostics.redact("https://user:secret@example.com/path?token=hidden")
        self.assertEqual(result, "https://example.com")


if __name__ == "__main__":
    unittest.main()
