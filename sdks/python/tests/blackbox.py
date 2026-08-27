"""Black-box Python SDK test against an independently running real broker."""

import json
import os
from pathlib import Path

from abyss_sdk import BrokerApiError, BrokerClient
from abyss_sdk.plugin import AbyssPlugin


def main() -> None:
    startup_info = os.environ.get("ABYSS_BROKER_STARTUP_INFO")
    if not startup_info:
        raise RuntimeError("ABYSS_BROKER_STARTUP_INFO must point to a real broker")

    client = BrokerClient.from_startup_info(startup_info)
    startup = json.loads(Path(startup_info).read_text(encoding="utf-8"))
    unauthenticated = BrokerClient(base_url=f"http://{startup['api_addr']}")
    events = AbyssPlugin(plugin_id="blackbox.python-sdk").connect()

    assert client.get_health() == {"service": "abyss-broker", "status": "ok"}
    try:
        unauthenticated.get_mitm_config()
    except BrokerApiError as error:
        assert error.status == 401
    else:
        raise AssertionError("protected broker REST route accepted no bearer token")
    assert client.get_proxy_status()["lifecycle"] == "running"
    mitm = client.get_mitm_config()
    assert client.update_mitm_config(mitm) == mitm
    hooks = client.get_hooks_config()
    hooks["harness_usage"]["config"]["harnesses"]["python-sdk-custom"] = {
        "enabled": True,
        "matchers": [{"process_names": ["python-sdk-custom"]}],
    }
    updated_hooks = client.update_hooks_config(hooks)
    assert (
        updated_hooks["harness_usage"]["config"]["harnesses"]["python-sdk-custom"]
        == hooks["harness_usage"]["config"]["harnesses"]["python-sdk-custom"]
    )
    client.collect_broker_logs({"max_bytes_per_file": 4096})
    assert client.get_diagnostics()["schema_version"] == 1
    assert client.get_network_observations(10)["schema_version"] == 1
    client.get_traffic_snapshot()

    assert client.shutdown()["lifecycle"] == "stopped"
    assert list(events) == []
    assert events.close is not None and events.close.code == 100
    print("Python SDK real-broker black-box: ok")


if __name__ == "__main__":
    main()
