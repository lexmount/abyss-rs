"""Explicit protocol compatibility and reproducible model/endpoint selection."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

from scripts.agent_e2e_ci.model import ContractError


# Values are public API roots, without the operation suffix. This is a test
# catalog, not a model whitelist in the runtime. Override per route for regional
# keys, Coding Plans, or compatible gateways; never put credentials in a URL.
ROUTES = {
    "openai": {
        "responses": ("https://api.openai.com/v1", ["gpt-5", "gpt-5.3-codex"]),
        "chat": ("https://api.openai.com/v1", ["gpt-5"]),
    },
    "anthropic": {
        "messages": ("https://api.anthropic.com", ["claude-sonnet-5"]),
    },
    "deepseek": {
        "responses": (
            "https://api.deepseek.com",
            ["deepseek-flash", "deepseek-v4-pro"],
        ),
        "chat": ("https://api.deepseek.com", ["deepseek-flash", "deepseek-v4-pro"]),
        "messages": (
            "https://api.deepseek.com/anthropic",
            ["deepseek-flash", "deepseek-v4-pro"],
        ),
    },
    "glm": {
        "responses": ("https://open.bigmodel.cn/api/v1", ["glm-4.7"]),
        "chat": ("https://open.bigmodel.cn/api/paas/v4", ["glm-4.7"]),
        "messages": ("https://open.bigmodel.cn/api/anthropic", ["glm-4.7"]),
    },
    "kimi": {
        "responses": ("https://api.moonshot.cn/v1", ["kimi-k3"]),
        "chat": ("https://api.moonshot.cn/v1", ["kimi-k3"]),
        "messages": ("https://api.moonshot.cn/anthropic", ["kimi-k3"]),
    },
    "qwen": {
        "responses": (
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            ["qwen3.8-flash"],
        ),
        "chat": (
            "https://dashscope.aliyuncs.com/compatible-mode/v1",
            ["qwen3.8-flash"],
        ),
        "messages": (
            "https://dashscope.aliyuncs.com/apps/anthropic",
            ["qwen3.8-flash"],
        ),
    },
}
HARNESS_PROTOCOLS = {
    "codex": ("responses",),
    "claude-code": ("messages",),
    "deepseek-harness": ("responses", "chat", "messages"),
    "hermes": ("responses", "chat", "messages"),
}
PROVIDER_SECRETS = {
    "openai": "CODEX_API_KEY",
    "anthropic": "CLAUDE_CODE_API_KEY",
    "deepseek": "ABYSS_E2E_DEEPSEEK_API_KEY",
    "glm": "ABYSS_E2E_GLM_API_KEY",
    "kimi": "ABYSS_E2E_KIMI_API_KEY",
    "qwen": "ABYSS_E2E_QWEN_API_KEY",
}


@dataclass(frozen=True)
class MatrixCase:
    id: str
    harness: str
    provider: str
    protocol: str
    model: str
    base_url: str
    secret: str

    @property
    def host(self) -> str:
        return urlsplit(self.base_url).hostname or ""

    @property
    def event_provider(self) -> str:
        host = self.host
        for provider, domains in (
            ("openai", ("openai.com", "chatgpt.com")),
            ("anthropic", ("anthropic.com", "claude.ai")),
        ):
            if any(host == domain or host.endswith("." + domain) for domain in domains):
                return provider
        return host

    def as_dict(self) -> dict[str, str]:
        return asdict(self)

    def resource_id(self, run_id: str) -> str:
        # Docker DNS labels include a long service prefix and must stay <= 63
        # characters; the temporary certificate CN is also limited to 64 bytes.
        digest = hashlib.sha256((run_id + self.id).encode()).hexdigest()[:24]
        return "matrix-" + digest


class MatrixCatalog:
    def __init__(self, models: str = "", endpoints: str = "") -> None:
        self.models = self._overrides(models, "models")
        self.endpoints = self._overrides(endpoints, "endpoints")

    @staticmethod
    def _overrides(raw: str, kind: str) -> dict:
        try:
            values = json.loads(raw or "{}")
        except json.JSONDecodeError as error:
            raise ContractError(f"matrix {kind} must be a JSON object") from error
        if not isinstance(values, dict):
            raise ContractError(f"matrix {kind} must be a JSON object")
        for provider, protocols in values.items():
            if provider not in ROUTES or not isinstance(protocols, dict):
                raise ContractError(
                    f"unknown provider or invalid routes in matrix {kind}"
                )
            for protocol, value in protocols.items():
                if protocol not in ROUTES[provider]:
                    raise ContractError(f"unsupported route: {provider}/{protocol}")
                if kind == "models":
                    if (
                        not isinstance(value, list)
                        or not value
                        or len(value) != len(set(map(str, value)))
                    ):
                        raise ContractError("model lists must be nonempty and unique")
                    if any(
                        not isinstance(m, str)
                        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:-]{0,127}", m)
                        for m in value
                    ):
                        raise ContractError("invalid model identifier")
                else:
                    MatrixCatalog.validate_url(value)
        return values

    @staticmethod
    def validate_url(value: str) -> None:
        if not isinstance(value, str):
            raise ContractError("endpoint must be an HTTPS URL")
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username
            or parsed.password
            or parsed.query
            or parsed.fragment
            or any(c.isspace() for c in value)
        ):
            raise ContractError(
                "endpoint must be HTTPS without credentials, query, or fragment"
            )

    def cases(
        self,
        *,
        harness: str = "",
        provider: str = "",
        protocol: str = "",
        model: str = "",
    ) -> list[MatrixCase]:
        result = []
        for agent, supported in HARNESS_PROTOCOLS.items():
            for service, routes in ROUTES.items():
                for dialect, (default_url, default_models) in routes.items():
                    if dialect not in supported:
                        continue
                    url = (
                        self.endpoints.get(service, {})
                        .get(dialect, default_url)
                        .rstrip("/")
                    )
                    for selected_model in self.models.get(service, {}).get(
                        dialect, default_models
                    ):
                        if any(
                            expected and expected != actual
                            for expected, actual in (
                                (harness, agent),
                                (provider, service),
                                (protocol, dialect),
                                (model, selected_model),
                            )
                        ):
                            continue
                        identity = f"{agent}-{service}-{dialect}-{selected_model}"
                        suffix = hashlib.sha256(identity.encode()).hexdigest()[:8]
                        slug = re.sub(r"[^a-z0-9-]", "-", identity.lower())[:65]
                        result.append(
                            MatrixCase(
                                f"{slug}-{suffix}",
                                agent,
                                service,
                                dialect,
                                selected_model,
                                url,
                                PROVIDER_SECRETS[service],
                            )
                        )
        if not result:
            raise ContractError("matrix selection matches no supported combinations")
        if len(result) > 256:
            raise ContractError("matrix exceeds the GitHub Actions limit of 256 jobs")
        return result
