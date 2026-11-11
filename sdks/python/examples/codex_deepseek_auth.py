"""Replace Codex's DeepSeek bearer token using a broker request plugin."""

import argparse
import logging
from pathlib import Path

from abyss_sdk.plugin import AgentRequestContext, BrokerPlugin, ModifyAction, RequestDecision


class CodexDeepSeekAuth:
    """Supply a local credential only to Codex requests targeting DeepSeek."""

    def __init__(self, api_key: str) -> None:
        self._api_key = api_key

    def inspect(self, context: AgentRequestContext) -> RequestDecision:
        host = context.server_name or context.destination_host
        if (
            context.harness is None
            or context.harness.id != "codex"
            or host != "api.deepseek.com"
            or not context.auth_token_writable
        ):
            return RequestDecision.allow()

        logging.info("Replacing Codex DeepSeek authorization: request_id=%s", context.request_id)
        return RequestDecision.modify([ModifyAction.set_auth_token(self._api_key)])


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--key-file",
        type=Path,
        default=Path.home() / ".deepseek/api.key",
        help="Plain-text API key file (default: ~/.deepseek/api.key)",
    )
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    auth = CodexDeepSeekAuth(args.key_file.expanduser().read_text(encoding="utf-8").strip())
    plugin = BrokerPlugin(
        "example.codex-deepseek-auth", on_agent_request=auth.inspect, agent_events=False
    )
    stream = plugin.connect()
    logging.info("Codex DeepSeek auth plugin connected")
    try:
        for _event in stream:
            pass
    finally:
        stream.close_stream()


if __name__ == "__main__":
    main()
