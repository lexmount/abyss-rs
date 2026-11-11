"""Route Codex HTTP model requests to DeepSeek through an Abyss plugin."""

import argparse
import logging
from pathlib import Path
from urllib.parse import urlsplit

from abyss_sdk.plugin import AgentRequestContext, BrokerPlugin, ModifyAction, RequestDecision


class CodexDeepSeekProvider:
    """Select the provider URL, model and credential as one request decision."""

    def __init__(self, api_key: str, model: str = "deepseek-flash") -> None:
        self._api_key = api_key
        self._model = model

    def inspect(self, context: AgentRequestContext) -> RequestDecision:
        if (
            context.harness is None
            or context.harness.id != "codex"
            or urlsplit(context.base_url or "").hostname not in ("api.openai.com", "chatgpt.com")
            or not context.base_url_writable
            or not context.auth_token_writable
            or not context.model_writable
        ):
            return RequestDecision.allow()

        logging.info("Routing Codex to DeepSeek: request_id=%s", context.request_id)
        return RequestDecision.modify(
            [
                ModifyAction.set_base_url("https://api.deepseek.com"),
                ModifyAction.set_auth_token(self._api_key),
                ModifyAction.set_model(self._model),
            ]
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-file", type=Path, default=Path.home() / ".deepseek/api.key")
    parser.add_argument("--model", default="deepseek-flash")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    provider = CodexDeepSeekProvider(args.key_file.expanduser().read_text().strip(), args.model)
    plugin = BrokerPlugin(
        "example.codex-deepseek-provider", on_agent_request=provider.inspect, agent_events=False
    )
    stream = plugin.connect()
    logging.info("Codex DeepSeek provider plugin connected")
    try:
        for _event in stream:
            pass
    finally:
        stream.close_stream()


if __name__ == "__main__":
    main()
