"""Runtime configuration derived from the self-hosted CI environment."""

from __future__ import annotations

import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path

from .model import MAX_SCENARIOS, ContractError


RUN_ID_PATTERN = re.compile(r"[^A-Za-z0-9_.-]+")
BACKEND_IMAGE_PATTERN = re.compile(
    r"^docker\.io/lexmount/abyss-backend@sha256:[0-9a-f]{64}$"
)


@dataclass(frozen=True)
class RuntimeConfig:
    """All externally configurable values for one isolated CI run."""

    repo_root: Path
    runtime_root: Path
    run_id: str
    seed: int
    max_scenarios: int
    backend_image: str
    backend_platform: str
    postgres_image: str
    generator_model: str | None
    b_model: str | None
    judge_model: str | None
    codex_timeout_seconds: int
    startup_timeout_seconds: int
    event_timeout_seconds: int

    @property
    def package_root(self) -> Path:
        return self.repo_root / "scripts" / "agent_e2e_ci"

    @property
    def artifact_root(self) -> Path:
        return self.runtime_root / "artifacts"

    @classmethod
    def from_environment(cls) -> "RuntimeConfig":
        repo_root = Path(__file__).resolve().parents[2]
        run_id = cls._run_id()
        runner_temp = Path(os.environ.get("RUNNER_TEMP", "/tmp"))
        configured_root = os.environ.get("ABYSS_AGENT_E2E_RUNTIME_ROOT")
        runtime_root = (
            Path(configured_root).expanduser().resolve()
            if configured_root
            else runner_temp / f"abyss-agent-e2e-ci-{run_id}"
        )
        seed_value = os.environ.get("ABYSS_AGENT_E2E_SEED")
        seed = (
            secrets.randbits(63)
            if not seed_value
            else cls._integer(seed_value, "seed", 0, 2**63 - 1)
        )
        max_scenarios = cls._integer(
            os.environ.get("ABYSS_AGENT_E2E_MAX_SCENARIOS", "2"),
            "max scenarios",
            1,
            MAX_SCENARIOS,
        )
        backend_image = os.environ.get("ABYSS_AGENT_E2E_BACKEND_IMAGE")
        if backend_image is None:
            image_file = repo_root / "scripts" / "ci" / "abyss-backend-image.txt"
            backend_image = image_file.read_text(encoding="utf-8").strip()
            if not BACKEND_IMAGE_PATTERN.fullmatch(backend_image):
                raise ContractError(
                    f"{image_file} must contain one digest-pinned public Backend image"
                )
        return cls(
            repo_root=repo_root,
            runtime_root=runtime_root,
            run_id=run_id,
            seed=seed,
            max_scenarios=max_scenarios,
            backend_image=backend_image,
            backend_platform=os.environ.get(
                "ABYSS_AGENT_E2E_BACKEND_PLATFORM", "linux/amd64"
            ),
            postgres_image=os.environ.get("ABYSS_AGENT_E2E_POSTGRES_IMAGE", "postgres:16"),
            generator_model=os.environ.get("ABYSS_AGENT_E2E_GENERATOR_MODEL") or None,
            b_model=os.environ.get("ABYSS_AGENT_E2E_B_MODEL") or None,
            judge_model=os.environ.get("ABYSS_AGENT_E2E_JUDGE_MODEL") or None,
            codex_timeout_seconds=cls._integer(
                os.environ.get("ABYSS_AGENT_E2E_CODEX_TIMEOUT_SECONDS", "600"),
                "Codex timeout",
                60,
                1_800,
            ),
            startup_timeout_seconds=cls._integer(
                os.environ.get("ABYSS_AGENT_E2E_STARTUP_TIMEOUT_SECONDS", "180"),
                "startup timeout",
                30,
                600,
            ),
            event_timeout_seconds=cls._integer(
                os.environ.get("ABYSS_AGENT_E2E_EVENT_TIMEOUT_SECONDS", "60"),
                "event timeout",
                10,
                300,
            ),
        )

    @staticmethod
    def _run_id() -> str:
        explicit = os.environ.get("ABYSS_AGENT_E2E_RUN_ID")
        if explicit:
            raw = explicit
        else:
            github_run = os.environ.get("GITHUB_RUN_ID", "local")
            attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
            raw = f"{github_run}-{attempt}-{secrets.token_hex(4)}"
        normalized = RUN_ID_PATTERN.sub("-", raw).strip("-.")[:80]
        if not normalized:
            raise ContractError("ABYSS_AGENT_E2E_RUN_ID contains no usable characters")
        return normalized

    @staticmethod
    def _integer(value: str, label: str, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except ValueError as error:
            raise ContractError(f"{label} must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise ContractError(f"{label} must be between {minimum} and {maximum}")
        return parsed
