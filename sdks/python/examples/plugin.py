"""Minimal synchronous broker plugin."""

from abyss_sdk.plugin import BrokerPlugin


def main() -> None:
    plugin = BrokerPlugin(plugin_id="example.python")
    close = plugin.run(lambda event: print(event.event_id))
    print(f"broker closed plugin stream: {close.code} {close.reason}")


if __name__ == "__main__":
    main()
