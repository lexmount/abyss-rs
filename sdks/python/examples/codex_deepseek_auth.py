"""Supply Codex credentials/model after a configured MITM redirect to DeepSeek."""

import os
from pathlib import Path

from abyss_sdk.plugin import AgentRequestContext, BrokerPlugin, ModifyAction, RequestDecision

TOKEN = (
    Path(os.environ.get("DEEPSEEK_API_KEY_FILE", "~/.deepseek/api.key"))
    .expanduser()
    .read_text()
    .strip()
)
MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")


def inspect(context: AgentRequestContext) -> RequestDecision:
    if (
        context.harness is None
        or context.harness.id != "codex"
        or context.authority != "api.deepseek.com"
    ):
        return RequestDecision.allow()
    actions = []
    if context.auth_token_writable:
        actions.append(ModifyAction.set_auth_token(TOKEN))
    if context.model_writable:
        actions.append(ModifyAction.set_model(MODEL))
    return RequestDecision.modify(actions) if actions else RequestDecision.allow()


if __name__ == "__main__":
    stream = BrokerPlugin(
        "example.codex-deepseek-auth", on_agent_request=inspect, agent_events=False
    ).connect()
    print("Codex DeepSeek auth plugin connected", flush=True)
    for _ in stream:
        pass
