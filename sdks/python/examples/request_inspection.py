"""A marker check illustrating the callback, not a complete data-loss policy."""

from abyss_sdk.plugin import AgentRequestContext, BrokerPlugin, RequestDecision


def inspect(context: AgentRequestContext) -> RequestDecision:
    detected = context.agent is not None and any(
        "PRIVATE KEY" in message.text for message in context.agent.conversation.entries
    )
    return RequestDecision(not detected, "Private key detected" if detected else None)


if __name__ == "__main__":
    BrokerPlugin("example.python-policy", on_agent_request=inspect, agent_events=False).run()
