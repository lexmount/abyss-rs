"""Self-hosted runner capability checks with no installation side effects."""

from __future__ import annotations

import platform
import shutil
from dataclasses import dataclass

from .process import CommandRunner, OrchestrationError


REQUIRED_COMMANDS = ("bash", "cargo", "codex", "docker", "git", "openssl", "python3")
REQUIRED_CODEX_EXEC_OPTIONS = (
    "--json",
    "--image",
    "--ephemeral",
    "--ignore-user-config",
    "--ignore-rules",
    "--output-schema",
    "--output-last-message",
    "--skip-git-repo-check",
    "--sandbox",
)


@dataclass(frozen=True)
class PreflightResult:
    """Version evidence retained in the semantic bundle and job summary."""

    codex_version: str
    cargo_version: str
    docker_version: str
    openssl_version: str
    python_version: str

    def as_dict(self) -> dict[str, str]:
        return {
            "codex": self.codex_version,
            "cargo": self.cargo_version,
            "docker": self.docker_version,
            "openssl": self.openssl_version,
            "python": self.python_version,
        }


class RunnerPreflight:
    """Verifies the runner is ready without downloading or modifying it."""

    def __init__(self, commands: CommandRunner) -> None:
        self.commands = commands

    def run(self) -> PreflightResult:
        issues: list[str] = []
        if platform.system() != "Linux":
            issues.append("Agent E2E CI requires a Linux self-hosted runner")
        missing = [command for command in REQUIRED_COMMANDS if shutil.which(command) is None]
        if missing:
            issues.append(
                f"missing required commands: {', '.join(missing)}"
            )
        if "docker" not in missing:
            docker_info = self.commands.run(
                ["docker", "info"],
                timeout=30,
                check=False,
            )
            if docker_info.returncode != 0:
                detail = docker_info.stderr.strip() or docker_info.stdout.strip()
                issues.append(f"Docker broker is unavailable: {detail[-1_000:]}")
        if "codex" not in missing:
            login = self.commands.run(
                ["codex", "login", "status"],
                timeout=30,
                check=False,
            )
            if login.returncode != 0:
                issues.append(
                    "Codex CLI is not authenticated for the runner service account"
                )
            help_result = self.commands.run(
                ["codex", "exec", "--help"],
                timeout=30,
                check=False,
            )
            if help_result.returncode != 0:
                issues.append("Codex CLI could not display exec capabilities")
            else:
                missing_options = [
                    option
                    for option in REQUIRED_CODEX_EXEC_OPTIONS
                    if option not in help_result.stdout
                ]
                if missing_options:
                    issues.append(
                        "Codex CLI lacks required exec options: "
                        + ", ".join(missing_options)
                    )
        if issues:
            raise OrchestrationError("runner preflight failed:\n- " + "\n- ".join(issues))
        return PreflightResult(
            codex_version=self._version(["codex", "--version"]),
            cargo_version=self._version(["cargo", "--version"]),
            docker_version=self._version(["docker", "--version"]),
            openssl_version=self._version(["openssl", "version"]),
            python_version=self._version(["python3", "--version"]),
        )

    def _version(self, arguments: list[str]) -> str:
        result = self.commands.run(arguments, timeout=30)
        return (result.stdout.strip() or result.stderr.strip())[:500]
