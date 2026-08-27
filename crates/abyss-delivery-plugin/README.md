# Abyss Delivery Plugin

`abyss-delivery-plugin` is the official out-of-process HTTP consumer for
`abyss-broker` Agent events. The broker never reads this plugin's destination,
credential, or failed-delivery spool.

With no configuration, the plugin connects through normal `abyss-sdk`
discovery and sends events without authentication to
`http://127.0.0.1:8080/v1/agent-usage/events`. Packaged products pass their
shared `product-config.json`; delivery settings live under `delivery_worker`:

```json
{
  "schema_version": 1,
  "product": {
    "kind": "host"
  },
  "delivery_worker": {
    "plugin_id": "lexmount.abyss.delivery",
    "delivery": {
      "endpoint": "https://abyss.example.com/v1/agent-usage/events",
      "spool_enabled": true,
      "spool_path": "delivery/failed-events.jsonl"
    },
    "authentication": {
      "mode": "managed_bearer"
    }
  }
}
```

In managed mode, the CLI or Host App performs SSO and hot-updates the worker
through the v1 Delivery Control API documented at
`specs/delivery-control/v1/README.md`. The worker keeps the synchronized token
only in memory; the owning product resends its authoritative stored credential
after a worker restart. Login, refresh, and logout do not restart the worker.
Static `authorization_header_file` and
`cookie_header_file` modes remain available for deployments that provision a
complete header file. Relative credential and spool paths are resolved from the
configuration file directory. Changing the endpoint or authentication mode
requires only a process restart, not a rebuild.

The SDK discovers the broker endpoint in this order:

1. `broker_endpoint` in the plugin configuration;
2. `ABYSS_BROKER_PLUGIN_ENDPOINT`;
3. the JSON file named by `ABYSS_BROKER_STARTUP_INFO`;
4. `$ABYSS_HOME/runtime/startup-info.json`.

Unix platforms use a Unix domain socket. Windows uses the Named Pipe endpoint
advertised in the same startup information contract.

Product launchers may additionally pass `--startup-info-file`. A launcher that
owns the broker process also passes `--broker-pid`; a system process manager can
instead point `ABYSS_BROKER_STARTUP_INFO` at the broker-owned startup record.
The worker writes its selected readiness path only after its loopback control
listener is bound and the broker accepts the plugin handshake. The record
contains both process IDs plus the control endpoint and local token-file path.
It removes the record and token when the event stream closes. These private
lifecycle flags let a product distinguish a connected worker from a process
that was merely spawned; they do not add plugin management to the public CLI.
