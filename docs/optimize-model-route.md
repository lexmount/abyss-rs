# Model routing in the endpoint runtime

The endpoint distribution owns the official model-routing plugin. The standalone CLI and the native applications use the same catalog validation, model discovery, credential selection and broker decisions. Catalog sources are opened by the interactive client. Provider credentials and the management-service login never appear in status output.

The worker keeps an immutable routing snapshot for each authenticated user. A successful local REST update replaces the complete snapshot. Inference requests consult the snapshot for the attributed principal. The client continues to import local JSON and anonymous or same-origin authenticated service URLs. Changes to a provider assignment revoke obsolete selections. Restart recovery must preserve the last acknowledged update.

The release includes the plugin alongside the broker and delivery worker in both Unix CLI variants and the Windows runtime. The desktop consumer verifies the complete archive digest and pinned source revision before signing. The endpoint change must ship before the desktop release pin can advance.

Validation covers source and packaged installation, CLI and desktop command parity, rejected updates, user isolation, restart recovery, credential redaction and routing without profile reads on the request path. Live verification uses separate Codex and DSH sessions and observes the selected provider and model.

## CLI workflow

```sh
abyss model-route import-file ./providers.json
abyss model-route import-url https://config.example.org/catalog --sso
abyss model-route state
abyss model-route models example team
abyss model-route select codex example team model-a
abyss model-route disable codex
abyss model-route clear
```

Each import reads the selected source again. The optional SSO flag requires a current terminal login at the catalog URL's origin. The worker lists the catalog's configured models or makes an asynchronous request to the provider using the selected credential. Remote pagination runs within the local request lifetime and never holds the snapshot lock across a network wait. The CLI starts the worker on first use and reconnects it to subsequent CLI-owned broker processes.

## Local control and identity

The CLI, macOS Host and Windows Host each send HTTP/1.1 directly to the running plugin. Each caller opens files and downloads catalog URLs using its own credentials. The worker accepts only service startup arguments. A Unix-domain socket or Windows named pipe authenticates the OS principal on both ends. The broker handshake must succeed before the management endpoint reports ready. Resources under `/v1/model-route` use these operations.

| Operation | Result |
| --- | --- |
| GET or DELETE the base resource | Return redacted state or clear the caller's catalog and selections |
| PUT /catalog | Replace the catalog with the JSON configuration |
| PUT /selection | Set or disable a harness selection |
| POST /models | List models for the caller's provider and credential |
| GET /status | Return the connected broker's process ID |

All request and response bodies are JSON. The body of a catalog update is the catalog object itself, with `harness_providers` and `providers` at the top level. Each import retains selections whose assignments and credentials still resolve to the same provider endpoint. File paths and import URLs stay with the caller. A selection takes `{harness, selection}`, where selection is null to disable or contains provider, credential and model. Model discovery takes `{provider, credential, include_metadata?}` and returns an array of IDs or objects with an ID and optional creation time. Mutations return the redacted state. Errors return a non-success status and an `error` string. Clients cap imported catalogs at 2 MiB and REST messages at 4 MiB. The service returns fixed-length JSON responses and closes the HTTP/1.1 connection. The Unix system socket is `model-route.sock` beside the broker startup file. On Windows the system pipe is `\\.\pipe\abyss-model-route-v1`. Clients verify the connected service identity before sending credentials.

The worker serializes updates, writes a private temporary file, flushes it, atomically replaces the durable profile and then publishes the new snapshot. Failed updates leave the previous selection active. The worker selects a user's snapshot using the broker-supplied source PID. For an inspected loopback explicit-proxy request the broker can resolve the client PID from both endpoints of the established OS TCP socket. Remote or unattributable connections retain the original model and destination.

A credential may include `proxy`, with `protocol` (`http`, `https` or `socks5`), `host`, `port` and optional paired `username` and `password`. Model Route passes the selected proxy to the broker through the generic `set_upstream_proxy` action. A selected HTTP model request or WebSocket upgrade uses this hop even when the provider hostname stays the same. An unavailable selected proxy fails that exchange. Credentials without a proxy retain the broker route. Other client traffic and initial protocol negotiation use the broker network configuration. Configure its upstream as well when the entire client must use a proxy. Remote model discovery also uses the selected credential's proxy.

For a Claude subscription, import `{"kind":"account","login":"<claude-account-id>","secret":"<current-access-token>"}` under the `anthropic` provider. The adapter recognizes Claude subscription access tokens beginning with `sk-ant-oat01-`. Model discovery and inference use the token as a bearer credential. Import a fresh token when it expires. Management status excludes account and proxy secrets.

The worker's protocol tests cover REST requests, restart recovery and a selected inference request with the durable file removed. The CLI black box covers local and HTTP imports, SSO origin checks and commands issued while only the running worker is available. The desktop consumer documents installer integration in its [companion design](https://github.com/lexmount/AbyssApp/blob/task/optimize-model-route/docs/optimize-model-route.md).

The coordinated changes are tracked in [endpoint PR 103](https://github.com/lexmount/abyss-rs/pull/103) and [desktop PR 100](https://github.com/lexmount/AbyssApp/pull/100).
