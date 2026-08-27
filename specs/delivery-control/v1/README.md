# Abyss Delivery Control Protocol v1

This protocol is the product-private control boundary between an Abyss product
(`abyss` CLI or Abyss Host App) and its packaged
`abyss-delivery-plugin` process. It is not part of the broker plugin protocol or
the public `abyss-sdk`.

The broker publishes normalized `AgentEvent` values and never receives a
remote endpoint, SSO configuration, access token, upload result, or spool
state. The delivery worker owns HTTP upload, remote authentication state, 401
handling, and failed-event replay.

```text
CLI / Host App                    abyss-delivery-plugin         abyss-broker
  SSO login                               |                         |
  PUT bearer credential ---------------->|                         |
                                          |<----- AgentEvent -------|
                                          |------ HTTP ingest -----> backend
  GET delivery status ------------------>|                         |
  DELETE bearer credential ------------>|                         |
```

## Discovery and local authentication

The worker binds an ephemeral IPv4 loopback port. After both the control
listener and broker plugin handshake are ready, it atomically writes the
product-requested startup record:

```json
{
  "worker_pid": 1234,
  "broker_pid": 1200,
  "control_endpoint": "http://127.0.0.1:49152",
  "control_token_file": "/product/runtime/delivery-control.token"
}
```

The token file contains a fresh random bearer token for the current worker
process. Every control request must send it as `Authorization: Bearer <token>`.
Products must validate that the endpoint is loopback and that the startup
record identifies the expected worker and broker processes before using it.
The worker removes its token and matching startup record on shutdown.

CLI runtime files are owner-only. A Host worker runs as a privileged service,
so its package may make these two control files readable by the product's
interactive-user group while keeping the containing runtime directory private.
The remote SSO token is never stored in either discovery file.

## Authentication modes

The `delivery_worker.authentication` section in the product-owned
`product-config.json` selects one of the following modes:

- `none`: send without remote authentication;
- `authorization_header_file`: read a static complete Authorization header at
  worker startup;
- `cookie_header_file`: read a static complete Cookie header at worker startup;
- `managed_bearer`: accept a bearer credential through this control protocol
  and keep it only in the running worker's memory.

Only `managed_bearer` accepts credential mutation. Changing the delivery
endpoint or authentication mode requires a worker restart. Setting, refreshing,
or clearing a managed bearer credential is a hot operation and must not restart
the worker or disconnect it from the broker.

## Endpoints

### `PUT /v1/delivery/auth`

Installs or refreshes a managed bearer credential.

```json
{
  "bearer_token": "opaque-native-session-token",
  "audience": "https://abyss.example.com"
}
```

`audience` must have the same HTTP origin (scheme, host, and effective port) as
the configured delivery endpoint. The worker makes the credential active, then
immediately attempts to replay the failed-event spool. The bearer value is
never persisted or returned.

### `DELETE /v1/delivery/auth`

Removes the in-memory managed credential. New events remain the worker's
responsibility and are appended to its spool until another credential is
installed.

### `GET /v1/delivery/status`

Returns non-secret operational state:

```json
{
  "endpoint": "https://abyss.example.com/v1/agent-usage/events",
  "authentication_mode": "managed_bearer",
  "authentication_state": "configured",
  "spooled_events": 0
}
```

Authentication state is one of `not_required`, `configured`, `missing`, or
`auth_required`. A remote HTTP 401 moves managed
authentication to `auth_required`; the rejected event is spooled and further
events are spooled without repeatedly sending the rejected credential.

## Persistence and replay

The failed-event spool is runtime state, not package payload. The authoritative
credential remains in the CLI credential store, macOS Keychain, or Windows
protected credential store. A restarted worker begins in `missing` state and
the owning product synchronizes its current credential only after the worker
has advertised its configured destination. This prevents a package
configuration change from forwarding a credential to a different origin.

Replay runs after every successful credential update. Delivery, credential
mutation, and replay share one serialization boundary so an old 401 response
cannot invalidate a freshly installed token and a live event cannot race an
atomic spool rewrite. Successfully replayed records are removed; undelivered
records remain durable.

## Product behavior

The CLI and Host App use the same state transitions:

- runtime startup restores the product credential to a managed worker;
- successful login installs the new credential and triggers replay;
- token refresh replaces it without a process restart;
- logout and authentication-expiry acknowledgement clear it locally;
- SSO-disabled products clear any stale managed credential.

The only platform difference is lifecycle and file access: the CLI owns a
same-user worker, while Host packages supervise a privileged worker and grant
their GUI narrowly scoped read access to its discovery/token files.
