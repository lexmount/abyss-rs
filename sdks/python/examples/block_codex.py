"""Block parsed Codex model requests through the existing plugin connection."""

from abyss_sdk.plugin import AgentRequestContext, BrokerPlugin, RequestDecision


def inspect(context: AgentRequestContext) -> RequestDecision:
    # Allow setup requests and WebSocket upgrades. Decide once the shared
    # parser provides the model request, including WebSocket prewarm messages.
    blocked = (
        context.harness is not None and context.harness.id == "codex" and context.agent is not None
    )
    return RequestDecision(
        not blocked,
        "Blocked by abyss-broker: Codex model requests are disabled by example.block-codex."
        if blocked
        else None,
    )


if __name__ == "__main__":
    BrokerPlugin("example.block-codex", on_agent_request=inspect, agent_events=False).run()
