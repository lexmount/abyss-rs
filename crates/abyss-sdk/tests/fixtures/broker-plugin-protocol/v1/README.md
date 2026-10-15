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

The version 1 maximum JSON payload is 64 MiB. A future transport implementation
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

Protocol version 1 carries one flat, normalized `AgentEvent` shape with
structured, role-aware conversation content. Consumers read messages directly
without decoding provider transport bodies. Raw transport bytes, decoded
provider documents, and original content blocks are not part of the contract.

```json
{
  "event_id": "evt-123",
  "occurred_at": "2026-08-19T10:00:00Z",
  "device": {
    "host_name": "developer-mac",
    "platform": "macos",
    "os_version": "15.6"
  },
  "agent": {
    "name": "codex",
    "version": "1.2.3"
  },
  "session_id": "session-123",
  "turn_id": "turn-123",
  "naming_thread": true,
  "stream_id": "thread-123",
  "response_id": "resp-123",
  "previous_response_id": "resp-122",
  "purpose": "session_title",
  "session_title": "Repository overview",
  "llm": {
    "provider": "openai",
    "model": "gpt-5"
  },
  "side": "response",
  "text": "I will inspect the repository.",
  "token_usage": {
    "input_tokens": 0,
    "output_tokens": 12,
    "cache_read_tokens": 0,
    "cache_write_tokens": 0,
    "reasoning_tokens": 4,
    "total_tokens": 12
  },
  "tool_calls": [
    {
      "call_id": "call-123",
      "name": "exec",
      "input": "pwd",
      "input_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  ],
  "attachments": [
    {
      "position": 0,
      "media_type": "image/png",
      "byte_size": 8,
      "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "content_base64": "iVBORw0KGgo="
    }
  ],
  "conversation": {
    "messages": [
      {
        "id": "rs-123",
        "role": "reasoning",
        "text": "The user wants an overview of the repository."
      },
      {
        "id": "msg-123",
        "role": "assistant",
        "text": "I will inspect the repository."
      },
      {
        "id": "fc-123",
        "role": "tool",
        "text": ""
      }
    ],
    "instructions_present": false,
    "completeness": "complete",
    "policy_omitted": false
  }
}
```

There is no event kind discriminator or nested payload enum. `side` identifies
whether content and token usage belong to the Agent request or provider response.
Tool arguments and results use `tool_calls` and `tool_results`, and images use
`attachments`; the event has no arbitrary `metadata` object.

`token_usage` counters are disjoint regardless of how the provider reports
them. `input_tokens` counts input neither read from nor written into a provider
cache, `cache_read_tokens` and `cache_write_tokens` count the cached input, and
`output_tokens` counts model output including reasoning. `reasoning_tokens` is
the part of `output_tokens` spent on reasoning, and `total_tokens` is
`input_tokens + cache_read_tokens + cache_write_tokens + output_tokens`. Request
events carry the input-side counters and response events carry the output-side
counters, so summing both sides of one exchange never double-counts a token.

## Conversation

`conversation.messages` lists provider messages and standalone items in provider
order. Each message has exactly three fields:

- `id`: the provider message or item identifier, or `null` when none was sent.
- `role`: one of the roles below.
- `text`: the message's text projection.

| Role | Meaning |
| --- | --- |
| `system` | Provider system prompt, such as Anthropic `system`. |
| `developer` | Developer instructions, including OpenAI `instructions`. |
| `user` | End-user input. |
| `assistant` | Model-visible assistant output. |
| `reasoning` | Model reasoning, such as OpenAI reasoning summaries or Anthropic thinking. |
| `tool` | A tool call or tool result item, kept in position. |
| `unknown` | The provider did not declare a role. |

`text` never contains tool arguments or results; those are carried only by
`tool_calls` and `tool_results`. Images are carried only by `attachments`.

A request event carries the history as the agent sent it. Repeated messages,
such as the same user prompt sent twice, are retained as separate messages and
are not deduplicated. A response event carries the provider's output after the
collector assembles streamed fragments; a streamed reply appears as one message
with its complete text, never as per-delta fragments.

OpenAI reasoning items and Anthropic thinking blocks both become `reasoning`
messages. An Anthropic response message that contains thinking and text blocks
is split into `reasoning` and `assistant` messages that share the Anthropic
message id and keep the provider's block order.

`instructions_present` reports whether the request
carried explicit instructions or a system prompt, including an explicitly empty
one.

`completeness` reports whether the captured content was decoded completely
(`complete`), only partly because capture or decoding was incomplete
(`partial`), or not at all because no supported structured document was found
(`unsupported`). It is independent of whether the provider call succeeded.

`policy_omitted` is `true` only when the conversation-text content policy
omitted messages. Tool, image, and token policies govern `tool_calls`,
`tool_results`, `attachments`, and `token_usage` independently; they never change
`conversation` or set `policy_omitted`.

## Turns

There is no collector-counted `turn_index`. The collector keeps no turn state. `turn_id` names
the user turn a request works for, as the Agent declares it in its own request
headers. It is unique within the session and opaque to consumers, who number
turns themselves:

- Codex: `root_turn_id` from `x-codex-turn-metadata`. On the main thread it
  equals the request's own `turn_id`; on a thread Codex opens for that turn,
  such as a guardian review, it names the user turn that thread works for.
- Claude Code: the `x-claude-code-prompt-id` header. Main-loop requests and the
  subagents they start carry the same value.
- Otherwise absent: the request works for no particular user turn. Examples are
  Claude Code auxiliary requests (recaps, input suggestions, naming calls, quota
  probes) and compaction, and other Anthropic clients. Consumers place such
  requests by their own rules.

A provider call identity is never substituted for a turn, so `turn_id` always
names a turn and never a single call.

## Naming threads

`naming_thread` is `true` when the request comes from a thread the Agent opened
only to name another session. Codex names a task from a separate session whose
`x-codex-turn-metadata` declares `thread_source` `thread_title`; the collector
reports those requests with `naming_thread` and does not forward the Agent's own
value. The field is omitted when `false`.

## Streams and continuation

Three optional fields place one exchange among the conversations of a session.
Both events of the exchange carry the same values, and each is omitted when
the traffic declares none:

- `stream_id`: the thread that sent the request, as the Agent declares it.
  Requests with the same value continue one conversation.
  - Codex: `thread_id` from `x-codex-turn-metadata`. The main thread's value
    equals the session id; a thread Codex opens for a turn, such as a guardian
    review, has its own value.
  - Claude Code: by `x-claude-code-request-class`, the session id
    (`x-claude-code-session-id`) for `main` requests and the subagent instance
    (`x-claude-code-agent-id`) for `subagent` requests. Other Claude Code
    requests carry none.
- `response_id`: the provider identity of the response the exchange produced:
  the OpenAI response id (`resp_…`) or the Anthropic message id (`msg_…`).
  Later requests name it to continue after that response.
- `previous_response_id`: the response the request continues after. The
  request then carries only the messages added since that response.
  - Anthropic: `previous_message_id` of a `thread` `continue` request.
  - OpenAI: the request's `previous_response_id`.

## Call purpose and session title

`purpose` states what the Agent made a provider call for, when its traffic
says so. Both events of the call carry it. Values:

- `session_title`: the Agent asks the model to name the session the call
  belongs to. Claude Code makes such a call with the naming instruction in its
  system prompt (`You are naming a coding session…`) and the billing header
  present.
- `compaction`: the Agent asks the model to summarize the conversation so far,
  to continue from the summary instead of the full history. Codex declares it
  as `request_kind` `compaction` in `x-codex-turn-metadata`, Claude Code as
  `x-claude-code-request-class` `compaction`.
- `prewarm`: an OpenAI Responses WebSocket client explicitly sends
  `response.create` with boolean `generate: false`. The connection is warmed
  without generating output. Both flat and nested `response` payloads are
  supported. Absent, true, or malformed flags do not declare prewarm.

Token counters always retain the provider's observations, including prewarm.
An all-traffic summary includes every event. Comparisons with Codex
`turn.completed.usage` use completed inference only, excluding events explicitly
marked `prewarm` and reporting their usage separately. Do not infer prewarm from
event order, empty replies, missing turn ids, or token differences. For comparison
with Codex, add Abyss's disjoint input/cache-read/cache-write counters to obtain
inclusive input; reasoning is already included in output and is not added again.

`session_title` is the title from the response side of a `session_title` call,
read only when the reply is a single `{"title": "…"}` object. It names the
event's own session. Like `text`, it is model output and is omitted when the
content policy drops conversation text.

For title generation, Codex uses a separate thread whose requests do not say
which session they name. Those naming events carry `naming_thread` instead of
`purpose: session_title` and `session_title`; Codex compaction calls can still
carry `purpose: compaction`.

The official delivery plugin stores both fields under the same names in the
usage-event metadata. The broker forwards them unchanged.

## Event identity and emission

Event ids are deterministic. The collector derives an id from the device,
agent, session, event side, provider response identity, and a content digest,
so observing the same exchange again yields the same id and ingestion stays
idempotent. Distinct provider calls produce distinct ids.

The broker emits events only for exchanges its Agent protocol parser accepted.
An exchange the parser rejects produces no event.

## Delivery

The official delivery plugin stores the conversation as `metadata.conversation`
and the purpose and title as `metadata.purpose` and `metadata.session_title`.
It sends `turn_id`, `naming_thread`, `stream_id`, `response_id`, and
`previous_response_id` as top-level fields of the backend usage event.
Backend titles and trajectories consume these fields without decoding provider
bodies. Other plugins may translate the event for their own destinations.

Rust, Python, and TypeScript SDKs all request protocol version 1 and consume this
same event shape with the same 64 MiB JSON frame limit. The broker forwards the
structured event without a legacy projection or a synthetic turn counter.

The complete event schema is in
[`agent-event.schema.json`](agent-event.schema.json).

## Versioning

`protocol_version` covers framing, handshake semantics, and the `AgentEvent`
contract. An event does not carry or negotiate a separate schema version.

During the current pre-release development phase, this single v1 contract is
updated in place. Earlier development shapes are not supported; the broker and
SDKs must be updated together. Once the protocol is published as stable,
incompatible changes require a new version and explicit negotiation support.
