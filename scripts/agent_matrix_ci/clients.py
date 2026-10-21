"""Native noninteractive client invocations; credentials exist only in child env."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from scripts.agent_e2e_ci.process import CommandRunner, OrchestrationError
from scripts.agent_e2e_ci.stack import TestStack

from .catalog import MatrixCase


class HeadlessClient:
    def __init__(self, case: MatrixCase, commands: CommandRunner) -> None:
        self.case = case
        self.commands = commands

    @property
    def executable(self) -> str:
        return {"codex": "codex", "claude-code": "claude", "deepseek-harness": "dsh"}[
            self.case.harness
        ]

    def preflight(self) -> dict[str, str]:
        required = (self.executable, "cargo", "docker", "openssl")
        missing = [name for name in required if not shutil.which(name)]
        if missing:
            raise OrchestrationError(
                "missing preinstalled commands: " + ", ".join(missing)
            )
        self.commands.run(["docker", "info"], timeout=30, label="Docker readiness")
        versions = {}
        for name in required:
            result = self.commands.run(
                [name, "version" if name == "openssl" else "--version"], timeout=30
            )
            versions[name] = (result.stdout or result.stderr).strip()[:500]
        options = {
            "codex": (
                "--ignore-user-config",
                "--ignore-rules",
                "--ephemeral",
                "--json",
            ),
            "claude": ("--bare", "--setting-sources", "--include-partial-messages"),
            "dsh": ("--profile", "--patch"),
        }
        command = (
            [self.executable, "exec", "--help"]
            if self.executable == "codex"
            else [self.executable, "--help"]
        )
        help_text = self.commands.run(command, timeout=30).stdout
        if any(option not in help_text for option in options[self.executable]):
            raise OrchestrationError(
                f"{self.executable} lacks required noninteractive options"
            )
        return versions

    @staticmethod
    def base_environment() -> dict[str, str]:
        # Do not inherit other providers' keys, login overrides, proxies, hooks,
        # NODE_OPTIONS or OTEL endpoints from a shared runner service account.
        allowed = (
            "PATH",
            "HOME",
            "USER",
            "LOGNAME",
            "LANG",
            "LC_ALL",
            "TMPDIR",
            "TMP",
            "TEMP",
            "SYSTEMROOT",
        )
        return {name: os.environ[name] for name in allowed if name in os.environ}

    def invocation(
        self, workspace: Path, stack: TestStack, key: str
    ) -> tuple[list[str], dict[str, str]]:
        case = self.case
        environment = self.base_environment()
        environment.update(
            {
                name: stack.proxy_url
                for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")
            }
        )
        environment.update(
            {
                "NO_PROXY": "localhost,127.0.0.1,::1",
                "no_proxy": "localhost,127.0.0.1,::1",
                "NODE_EXTRA_CA_CERTS": str(stack.ca_certificate),
                "CODEX_CA_CERTIFICATE": str(stack.ca_certificate),
                "SSL_CERT_FILE": str(stack.ca_certificate),
            }
        )
        if case.harness == "codex":
            environment["MATRIX_PROVIDER_KEY"] = key
            provider = (
                'model_providers.matrix={name="matrix",base_url='
                + json.dumps(case.base_url)
                + ',env_key="MATRIX_PROVIDER_KEY",wire_api="responses",request_max_retries=2,stream_max_retries=2}'
            )
            return [
                "codex",
                "exec",
                "--json",
                "--ephemeral",
                "--ignore-user-config",
                "--ignore-rules",
                "--skip-git-repo-check",
                "--sandbox",
                "read-only",
                "--cd",
                str(workspace),
                "-c",
                'model_provider="matrix"',
                "-c",
                provider,
                "-c",
                'model_reasoning_effort="low"',
                "--model",
                case.model,
                "--",
                "-",
            ], environment
        if case.harness == "claude-code":
            environment.update(
                {
                    "ANTHROPIC_API_KEY": key,
                    "ANTHROPIC_BASE_URL": case.base_url,
                    "ANTHROPIC_DEFAULT_HAIKU_MODEL": case.model,
                    "ANTHROPIC_DEFAULT_SONNET_MODEL": case.model,
                    "ANTHROPIC_DEFAULT_OPUS_MODEL": case.model,
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                }
            )
            return [
                "claude",
                "--bare",
                "--setting-sources",
                "",
                "--no-session-persistence",
                "--model",
                case.model,
                "--tools",
                "Read",
                "--allowedTools",
                "Read",
                "--permission-mode",
                "dontAsk",
                "--output-format",
                "stream-json",
                "--verbose",
                "--include-partial-messages",
                "--session-id",
                str(uuid.uuid4()),
                "--print",
            ], environment
        environment["MATRIX_PROVIDER_KEY"] = key
        environment["DSH_HOME"] = str(workspace.parent / "dsh-home")
        patch = workspace.parent / "dsh-patch.json"
        patch.write_text(
            json.dumps(self.dsh_patch(), indent=2) + "\n", encoding="utf-8"
        )
        # DSH headless takes its task as an argument, containing only a public
        # audit marker and instructions, never the hidden fixture or credentials.
        return [
            "dsh",
            "--profile",
            "headless",
            "--patch",
            str(patch),
            "--json",
        ], environment

    def dsh_patch(self) -> list[dict]:
        case = self.case
        native = case.protocol == "messages"
        provider = "deepseek-official" if native else "matrix"
        model = {"id": case.model, "contextWindow": 128000, "maxTokens": 4096}
        patch = [
            {
                "id": "agent-default-model",
                "config": {"provider": provider, "model": case.model},
            },
            {"id": "session-title-llm", "disabled": True},
            {"id": "session-telemetry-otel", "disabled": True},
        ]
        if native:
            patch.append(
                {
                    "id": "llm-deepseek",
                    "config": {
                        "apiKeyEnv": "MATRIX_PROVIDER_KEY",
                        "baseURL": case.base_url,
                        "maxTokens": 4096,
                        "models": [model],
                        "retryPolicy": {"mode": "normal", "maxRetries": 2},
                    },
                }
            )
        else:
            config = {
                "apiKeyEnv": "MATRIX_PROVIDER_KEY",
                "baseURL": case.base_url,
                "api": "openai-responses"
                if case.protocol == "responses"
                else "openai-completions",
                "models": [model],
            }
            if case.protocol == "chat" and case.provider != "openai":
                config["compat"] = {
                    "maxTokensField": "max_tokens",
                    "supportsDeveloperRole": False,
                }
                thinking = {"glm": "zai", "qwen": "qwen"}.get(case.provider)
                if thinking:
                    config["compat"]["thinkingFormat"] = thinking
            patch.append(
                {"id": "llm-pi-ai", "config": {"providers": {provider: config}}}
            )
        return patch
