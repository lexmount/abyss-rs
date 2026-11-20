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

Each import reads the selected source again. A source change clears obsolete selections. The optional SSO flag requires a current terminal login at the catalog URL's origin. Model discovery uses the selected credential. The CLI starts the worker on first use and reconnects it to subsequent CLI-owned broker processes.

## Local control and identity

The interactive helper validates the source before sending a local HTTP/1.1 request. A Unix-domain socket or Windows named pipe authenticates the OS principal on both ends. The broker handshake must succeed before the management endpoint reports ready. Resources under `/v1/model-route` use these operations.

| Operation | Result |
| --- | --- |
| GET or DELETE the base resource | Return redacted state or clear the caller's catalog and selections |
| PUT /catalog | Replace the catalog with the imported source and contents |
| PUT /selection | Set or disable a harness selection |
| GET or PUT /profile | Read the caller's private profile for credential-specific discovery, or restore a previous installation if no state exists |
| GET /status | Return the connected broker's process ID |

The worker serializes updates, writes a private temporary file, flushes it, atomically replaces the durable profile and then publishes the new snapshot. Failed updates leave the previous selection active. The worker selects a user's snapshot using the broker-supplied source PID. When the PID is unavailable, including on explicit proxy connections, the request passes through with its original model and destination.

The executable black-box tests in `crates/abyss-model-route/tests` cover file and service imports, restart recovery and a selected inference request with the durable file removed. The desktop consumer documents installer integration in its [companion design](https://github.com/lexmount/AbyssApp/blob/task/optimize-model-route/docs/optimize-model-route.md).

The coordinated changes are tracked in [endpoint PR 103](https://github.com/lexmount/abyss-rs/pull/103) and [desktop PR 100](https://github.com/lexmount/AbyssApp/pull/100).
