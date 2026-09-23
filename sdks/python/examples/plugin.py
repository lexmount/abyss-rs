"""Consume broker events using one startup information file."""

import argparse

from abyss_sdk import BrokerClient


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("startup_info", help="Broker startup-info.json path")
    args = parser.parse_args()
    broker = BrokerClient.from_startup_info(args.startup_info)
    close = broker.plugin("example.python").run(lambda event: print(event.event_id))
    print("Broker closed:", close.code, close.reason)


if __name__ == "__main__":
    main()
