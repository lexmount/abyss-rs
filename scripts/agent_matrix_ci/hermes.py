"""Hermes' supported CLI and session middleware in a disposable client home."""

from __future__ import annotations

import json
import shutil
import ssl
from pathlib import Path

from scripts.agent_e2e_ci.stack import TestStack

from .catalog import MatrixCase


class HermesClient:
    API_MODES = {
        "chat": "chat_completions",
        "responses": "codex_responses",
        "messages": "anthropic_messages",
    }

    def __init__(self, case: MatrixCase) -> None:
        self.case = case

    def invocation(
        self, workspace: Path, stack: TestStack, environment: dict[str, str]
    ) -> tuple[list[str], dict[str, str]]:
        home = workspace.parent / "hermes-home"
        home.mkdir(mode=0o700, exist_ok=True)
        bundle = home / "ca-bundle.pem"
        roots = ssl.create_default_context().get_ca_certs(binary_form=True)
        bundle.write_text(
            "".join(ssl.DER_cert_to_PEM_cert(cert) for cert in roots)
            + stack.ca_certificate.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        plugin = home / "plugins" / "abyss"
        plugin.mkdir(parents=True, exist_ok=True)
        source = Path(__file__).resolve().parents[2] / "integrations/hermes/abyss"
        for filename in ("__init__.py", "plugin.yaml"):
            shutil.copyfile(source / filename, plugin / filename)
        # JSON is valid YAML; the orchestrator itself needs only the stdlib.
        (home / "config.yaml").write_text(
            json.dumps(self.configuration(bundle), indent=2) + "\n", encoding="utf-8"
        )
        environment.update(
            HERMES_HOME=str(home),
            HERMES_DISABLE_LAZY_INSTALLS="1",
            SSL_CERT_FILE=str(bundle),
        )
        return [
            "hermes",
            "chat",
            "--cli",
            "--oneshot",
            "--ignore-rules",
            "--format",
            "stream-json",
            "--provider",
            "custom:matrix",
            "--model",
            self.case.model,
            "--reasoning",
            "none"
            if self.case.protocol == "chat" and self.case.provider == "openai"
            else "low",
            "--max-turns",
            "6",
            "--toolsets",
            "file",
        ], environment

    def configuration(self, bundle: Path) -> dict:
        return {
            "model": {"default": self.case.model, "provider": "custom:matrix"},
            "providers": {
                "matrix": {
                    "base_url": self.case.base_url,
                    "key_env": "MATRIX_PROVIDER_KEY",
                    "api_mode": self.API_MODES[self.case.protocol],
                    "default_model": self.case.model,
                    "ssl_ca_cert": str(bundle),
                }
            },
            "plugins": {"enabled": ["abyss"]},
            "memory": {"memory_enabled": False, "user_profile_enabled": False},
            "agent": {"max_turns": 6},
        }
