# Abyss Broker Plugin Protocol Version 1

## Scope

This directory is the language-neutral contract for consuming normalized Agent
events from `abyss-broker`.

Protocol version 1 defines:

- local stream framing;
- plugin-to-broker and broker-to-plugin frame payloads;
- a long-lived live event stream;
- the `AgentEvent` contract carried by protocol version 1.

It does not define plugin process discovery, process startup, remote upload, or
authentication. Those concerns belong to the product or third-party process
that owns the plugin.

## Transport and Framing

The transport is a reliable local byte stream:

| Platform | Transport |
| --- | --- |
| macOS | Unix domain socket |
| Linux | Unix domain socket |
| Windows | Named Pipe |

The broker listens and the plugin process connects. Every message is encoded as
one frame:

```text
+--------------------------+------------------------+
| payload_length: uint32be | UTF-8 JSON payload     |
+--------------------------+------------------------+
             4 bytes              payload_length
```

`payload_length` counts only the JSON payload bytes. One frame contains exactly
one JSON payload. Protocol version negotiation occurs in the first frame rather
than in the binary frame header.

The version 1 maximum JSON payload is 16 MiB. A future transport implementation
must reject a larger frame before allocating its declared payload.

## Session Sequence

The plugin initiates one long-lived session:

```text
plugin                                           broker
  |                                                |
  | PluginHello                                    |
  |----------------------------------------------->|
  |                                                |
  |                       BrokerHello | BrokerError |
  |<-----------------------------------------------|
  |                                                |
  |                                     AgentEvent |
  |<-----------------------------------------------|
  |                                                |
  |                                     AgentEvent |
  |<-----------------------------------------------|
  |                                                |
  |                            BrokerClose | ...    |
  |<-----------------------------------------------|
```

The plugin must send `PluginHello` before another payload. The broker's first
response is either `BrokerHello`, which accepts the session and confirms the
requested plugin protocol version, or `BrokerError`, which rejects the
handshake and is followed by connection close. Every subsequent `AgentEvent`
uses the event contract defined by the accepted protocol version.

After the handshake, the broker pushes one `AgentEvent` message for every new
normalized event while the plugin remains connected. The stream is idle when
there are no events. Frames sent on one connection preserve event order.

Version 1 is a live, best-effort stream. The broker does not retain events for
an offline plugin, wait for plugin processing, accept acknowledgements, or
replay events after reconnection. A plugin that needs reliable remote delivery
must persist an event after receiving it and own its later retry behavior.

Each plugin connection is independent. A slow or disconnected plugin must not
block Agent event production or delivery to other plugins. Before deliberately
closing an accepted session, the broker sends `BrokerClose` as its final frame.
An uncontrolled transport failure may still end with EOF and no close frame;
the plugin owns reconnection.

The initial broker keeps a 64-event broadcast ring shared by all accepted
connections. Each connection reads independently from that ring. Falling more
than 64 events behind closes only that connection with close code `101`.
Plugins subscribe after `PluginHello` validation and immediately before the
broker writes `BrokerHello`. Events produced before validation or while
disconnected are not replayed.

Version 1 allows simultaneous connections with the same `plugin_id`. The value
is used for diagnostics only and does not select, replace, or authenticate a
connection.

## Endpoint Discovery

The default Unix endpoint is
`$ABYSS_HOME/runtime/broker-plugin-v1.sock`. Linux falls back to
`$HOME/.abyss`; the installed macOS Host uses `/Library/Application
Support/Abyss` as its default root. Windows uses
`\\.\pipe\abyss.broker-plugin-v1-<product-root-hash>` so product-scoped
runtime roots do not collide. A Unix broker whose product-root path would
exceed the operating-system socket limit uses a stable hashed socket path under
`/tmp` with owner-only permissions.

When a product starts a dynamically addressed broker, the broker writes the
concrete plugin endpoint into its startup-info file. SDK implementations should
prefer that product-owned handoff over reconstructing platform paths.

## Frame Payloads

The connection phase and direction determine how to decode each frame:

- the plugin's first frame is a `PluginHello`;
- the broker's first frame is a `BrokerHello` or `BrokerError`;
- after `BrokerHello`, broker frames are `AgentEvent` values; and
- `BrokerClose`, when present, is the final frame of an accepted session.

The JSON payloads do not carry a separate message `type` discriminator. Session
phase determines whether the shared `{ "code", "reason" }` control shape is a
handshake `BrokerError` or a final `BrokerClose`. An `AgentEvent` is serialized
directly and is not nested under an `event` field. For example, the complete
successful handshake payloads are:

```json
{
  "protocol_version": 1,
  "plugin_id": "company-a-security-exporter"
}
```

```json
{
  "protocol_version": 1
}
```

The plugin identifier must contain 1 to 128 ASCII letters, digits, `.`, `_`, or
`-`. It describes the plugin connection and is not a remote authentication
credential.

Handshake rejection and deliberate close payloads use the same direct control
shape:

```json
{
  "code": 1,
  "reason": "unsupported protocol version"
}
```

Version 1 defines these handshake error codes:

| Code | Meaning |
| --- | --- |
| `1` | Unsupported protocol version |
| `2` | Invalid plugin handshake |
| `3` | Broker resource limit |

Version 1 defines these close codes after an accepted handshake:

| Code | Meaning |
| --- | --- |
| `100` | Broker shutdown |
| `101` | Plugin event stream is too slow |

After `BrokerHello`, version 1 is broker-to-plugin only. A plugin does not send
event acknowledgements, keepalives, or other application frames. Stream liveness
comes from the local transport; reconnect policy belongs to the plugin.

The complete frame payload schema is in
[`messages.schema.json`](messages.schema.json). Standard examples are in
[`fixtures/`](fixtures/).

## Agent Event Contract

Protocol version 1 defines one flat, normalized `AgentEvent` shape:

```json
{
  "event_id": "evt-123",
  "occurred_at": "2026-08-19T10:00:00Z",
  "device": {
    "host_name": "developer-mac",
    "platform": "macos"
  },
  "agent": {
    "name": "codex"
  },
  "session_id": "session-123",
  "turn_index": 1,
  "llm": {
    "provider": "openai",
    "model": "gpt-5"
  },
  "side": "request",
  "token_usage": {
    "input_tokens": 24,
    "output_tokens": 0,
    "cache_read_tokens": 8,
    "cache_write_tokens": 0,
    "reasoning_tokens": 0,
    "total_tokens": 24
  }
}
```

There is no event kind discriminator or nested payload enum because version 1
defines only this event shape. `side` identifies whether the normalized content
and token usage belong to an Agent request or provider response.

Provider-specific response identifiers, raw HTTP details, parser evidence, and
other internal correlation data are not part of the public event. The broker
uses them while parsing and normalizing traffic, then exposes only declared,
typed fields. Tool activity is represented by the structured `tool_calls` and
`tool_results` arrays with broker-normalized call identifiers and tool names;
the event does not contain an arbitrary `metadata` object.

The event is intentionally independent of the current Abyss backend ingest
request. An official or third-party delivery plugin translates it into its
configured destination API.

The complete event schema is in
[`agent-event.schema.json`](agent-event.schema.json).

## Versioning

`protocol_version` covers framing, handshake semantics, and the `AgentEvent`
contract. Any incompatible change to one of those parts requires a new plugin
protocol version. `AgentEvent` therefore does not carry or negotiate a separate
schema version.

Files under this `v1` directory are immutable once the protocol is published.
Compatible documentation corrections may be made without changing wire
meaning. Incompatible changes require a new versioned directory and explicit
negotiation support.
