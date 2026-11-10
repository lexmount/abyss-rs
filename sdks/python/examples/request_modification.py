"""Override a supported model through explicit semantic actions."""

import os

from abyss_sdk.plugin import AgentRequestContext, BrokerPlugin, ModifyAction, RequestDecision

MODEL = os.environ["ABYSS_MODEL_OVERRIDE"]


def inspect(context: AgentRequestContext) -> RequestDecision:
    if context.model_writable:
        return RequestDecision.modify([ModifyAction.set_model(MODEL)])
    return RequestDecision.allow()


if __name__ == "__main__":
    BrokerPlugin("example.model-override", on_agent_request=inspect, agent_events=False).run()
