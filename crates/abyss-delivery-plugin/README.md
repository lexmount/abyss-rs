# Abyss Delivery Plugin

`abyss-delivery-plugin` is the official out-of-process HTTP consumer for
`abyss-broker` Agent events. The broker never reads this plugin's destination,
credential, or failed-delivery spool.

With no configuration, the plugin loads broker endpoints from startup information
and sends events without authentication to
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

The worker creates one SDK `BrokerClient`, then calls `client.plugin(plugin_id)`.
It loads missing endpoints from the JSON file named by
`ABYSS_BROKER_STARTUP_INFO`, or `$ABYSS_HOME/runtime/startup-info.json`.
The startup record must contain both `api_addr` and `plugin_endpoint`; the worker
does not read the REST bearer token because it only consumes plugin events.

For manual configuration without startup information, set both `broker_api_url`
(the loopback HTTP URL) and `broker_endpoint` (the plugin socket or Named Pipe)
in `delivery_worker`. `broker_endpoint` takes precedence over
`ABYSS_BROKER_PLUGIN_ENDPOINT`, which takes precedence over the startup record.
An explicit `broker_api_url` likewise takes precedence over `api_addr`.
Existing configurations supplying only `broker_endpoint` must also supply the
REST URL or a broker startup record. Endpoint discovery stays in the worker;
the SDK plugin itself uses only the address retained by its `BrokerClient`.

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
