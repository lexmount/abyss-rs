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
  "observed_at": "2026-08-19T10:00:00Z",
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
  "response_id": "resp-123",
  "previous_response_id": "resp-122",
  "subagent_id": "agent-2",
  "parent_subagent_id": "agent-1",
  "turn_id": "turn-1",
  "purpose": "session_title",
  "llm": {
    "provider": "openai",
    "model": "gpt-5"
  },
  "side": "response",
  "token_usage": {
    "input_tokens": 0,
    "output_tokens": 12,
    "cache_read_tokens": 0,
    "cache_write_tokens": 0,
    "reasoning_tokens": 4,
    "total_tokens": 12
  },
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
    "entries": [
      {
        "role": "reasoning",
        "text": "The user wants an overview of the repository.",
        "item_id": "rs-123"
      },
      {
        "role": "assistant",
        "text": "I will inspect the repository.",
        "item_id": "msg-123"
      },
      {
        "role": "tool_call",
        "text": "pwd",
        "call_id": "call-123",
        "name": "exec",
        "item_id": "fc-123"
      }
    ],
    "completeness": "complete"
  },
  "path": "/v1/responses",
  "headers": [
    {
      "name": "content-type",
      "value": "text/event-stream"
    },
    {
      "name": "x-request-id",
      "value": "req-123"
    },
    {
      "name": "set-cookie",
      "value": "<redacted>"
    }
  ]
}
```

There is no event kind discriminator or nested payload enum. `side` identifies
whether content and token usage belong to the Agent request or provider response.
`conversation` entries are the only carrier of the side's content: text,
reasoning, tool calls, and tool results appear in position as entries, with no
flattened text or tool-call summary beside them; images use `attachments`.
The event has no arbitrary `metadata` object.

`token_usage` counters are disjoint regardless of how the provider reports
them. `input_tokens` counts input neither read from nor written into a provider
cache, `cache_read_tokens` and `cache_write_tokens` count the cached input, and
`output_tokens` counts model output including reasoning. `reasoning_tokens` is
the part of `output_tokens` spent on reasoning, and `total_tokens` is
`input_tokens + cache_read_tokens + cache_write_tokens + output_tokens`. Request
events carry the input-side counters and response events carry the output-side
counters, so summing both sides of one exchange never double-counts a token.

## Conversation

`conversation` has two fields:

- `entries`: one entry per protocol block or item, in provider order. Blocks
  are never merged or split.
- `completeness`: whether the captured body was decoded completely
  (`complete`), only partly because capture or decoding was incomplete
  (`partial`), or not at all because no supported structured document was
  found (`unsupported`). It is independent of whether the provider call
  succeeded.

Each entry has:

- `role`: one of the roles below.
- `text`: the visible text. A `tool_call` carries its arguments or input as
  sent; a `tool_result` carries its output.
- `call_id`: on `tool_call` and `tool_result` entries, the identifier that
  pairs a call with its result, when the protocol supplies one.
- `name`: on `tool_call` entries, the tool name, when the protocol supplies
  one.
- `item_id`: the identity of the item the entry belongs to, when the protocol
  supplies one. A model output keeps the identity its provider assigned when a
  later request sends it back as history, so the request entry carries the
  same value as the response entry that produced it.
  - OpenAI Responses: the `id` of the input or output item, verbatim (`msg_…`,
    `rs_…`, `fc_…`, `ctc_…`, and so on). All entries of an item that yields
    several, such as a message with several content parts, carry the same
    value.
  - Anthropic: on a `thinking` block, `thinking:` followed by the lowercase
    hex SHA-256 of the block's `signature` (for a streamed block, its
    `signature_delta` fragments joined in order); on a `redacted_thinking`
    block, the same over its `data`. A block without a signature has none, and
    no other block carries one; tool blocks pair by `call_id`.
  - Chat Completions: none.

The role of an entry follows from the protocol structure alone:

| Role | Anthropic | OpenAI Responses | Chat Completions |
| --- | --- | --- | --- |
| `system` | each block of the top-level `system`; text blocks of a `role: "system"` message | `role: "system"` messages | `system` |
| `developer` | — | `instructions`; each content part of a `role: "developer"` message | `developer` |
| `user` | `text` blocks of user messages | `input_text` of user messages | `user` |
| `assistant` | `text` blocks of assistant messages | `output_text`, `refusal` | assistant `content`, `refusal` |
| `reasoning` | `thinking`, `redacted_thinking` | `reasoning` (its content, else its summary) | assistant `reasoning_content` |
| `tool_call` | `tool_use`, `server_tool_use`, `mcp_tool_use` | every `*_call` item | each assistant `tool_calls[]` |
| `tool_result` | `tool_result`, every `*_tool_result` | every `*_output` item | `tool` |
| `unknown` | — | an item without a recognized `role`, such as `agent_message` | a message without a recognized `role` |

Any other block or content part keeps its visible text in the role of its
enclosing message, and any other Responses item in its own `role`; a tool part
inside message content, such as a `tool_result` part, contributes nothing.
A `thinking` or `redacted_thinking` block or a `reasoning` item produces its
entry even when it carries no readable text, such as a reasoning item with only
`encrypted_content`; the entry's `text` is then empty. A block, part, or item
that carries no text, such as an image or a tool definition, produces no entry;
images are carried by `attachments`. Chat Completions `reasoning_content`
precedes the content of its message.
Responses use the same table: Anthropic response content blocks and OpenAI
output items become entries the same way, after the collector assembles
streamed fragments, so a streamed block appears as one entry with its complete
text. A request event carries the history as the agent sent it; repeated
blocks are not deduplicated.

The leading `system` and `developer` entries of a request are its system
prompt; no separate flag marks them. A tool result pairs with its call by
`call_id`, and model output replayed as history matches the response that
produced it by `item_id`.

## Omitted content

`omitted` lists the content categories the active content policy left out of
the event, in the order `token_usage`, `conversation_text`, `tool_content`,
`images`; it is omitted when everything was kept. An omitted category keeps
the structure and empties the content, so consumers can tell "not present"
from "not retained":

- `conversation_text`: entries other than `tool_call` and `tool_result` keep
  their role and `item_id` with empty `text`.
- `tool_content`: `tool_call` and `tool_result` entries keep their role,
  `call_id`, `name`, and `item_id` with empty `text`.
- `images`: no attachment is carried.
- `token_usage`: every counter is zero.

## Continuation

Two optional fields link one exchange to the responses around it. Both events
of the exchange carry the same values, and each is omitted when the traffic
declares none:

- `response_id`: the provider identity of the response the exchange produced:
  the OpenAI response id (`resp_…`) or the Anthropic message id (`msg_…`).
  Later requests name it to continue after that response.
- `previous_response_id`: the response the request continues after. The
  request then carries only the messages added since that response.
  - Anthropic: `previous_message_id` of a `thread` `continue` request.
  - OpenAI: the request's `previous_response_id`.

## Declared subagent and root turn

Three optional fields carry what a client declares about its subagents and
turns. Each is read only from the request headers (the upgrade request for a
WebSocket connection), taken verbatim, and omitted when the request declares
none; the collector never substitutes a value. Both events of an exchange
carry the same values, and none enters the event id.

| Field | Meaning | Claude Code | Codex |
| --- | --- | --- | --- |
| `subagent_id` | The subagent the exchange belongs to; absent for the main agent and for side requests. | `x-claude-code-agent-id` | `thread-id`, only when the request carries `x-codex-parent-thread-id` |
| `parent_subagent_id` | The subagent that spawned it; absent when the main agent spawned it. | `x-claude-code-parent-agent-id` | `x-codex-parent-thread-id`, unless it equals the `session-id` header, which names the main thread |
| `turn_id` | The root turn the client declares: the user input the exchange ultimately works for. A subagent's exchanges carry the value of the turn that spawned it; an exchange the client makes for no turn carries none. | `x-claude-code-prompt-id` | the `root_turn_id` string of the `x-codex-turn-metadata` JSON object |

A header counts when its value is non-empty and valid UTF-8. A Codex
`turn_id` is read only when `x-codex-turn-metadata` is a JSON object whose
`root_turn_id` is a non-empty string. Cursor, Hermes, WorkBuddy, and OpenCode
declare only `turn_id`, each from one header of the request itself: Cursor
`x-request-id`, Hermes `x-hermes-turn-id`, WorkBuddy
`x-conversation-request-id`, and OpenCode `x-opencode-request`. Other clients
declare none of the fields. The headers themselves remain in `headers`.

## Path

`path` is the exchange's request target: its path and query exactly as the
request line named them, for example `/v1/messages?beta=true`. A WebSocket
connection names its target only on its handshake, so every event of the
connection carries the upgrade request's path. Both events of an exchange
carry it. The value is verbatim: the query is not redacted, and the content
policy does not govern it.

## Headers

`headers` lists the captured headers of the event's side: the request headers
on a request event and the response headers on a response event. A WebSocket
connection has headers only on its handshake, so every request event of the
connection carries the upgrade request's headers, and every response event
carries the `101 Switching Protocols` response's headers.

Each entry is `{"name", "value"}`, or `{"name", "value_base64"}` with the
standard base64 encoding of the bytes when the value is not valid UTF-8;
exactly one of the two is present. Entries follow the order of the captured
header map, which groups repeated names together in first-seen order, and
keep every duplicate. Names are lowercase, as the captured header map stores
them.

The values are verbatim except for credential redaction, applied once by the
collector: the values of `authorization`, `proxy-authorization`, `cookie`,
`set-cookie`, `api-key`, `x-api-key`, `x-goog-api-key`, `anthropic-api-key`,
`chatgpt-account-id`, and of any header whose name contains `token`, become
`<redacted>` and the names are kept. The content policy does not govern
headers. The list is omitted when empty.

## Call purpose

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

The official delivery plugin stores it as `metadata.purpose` in the usage-event
metadata. The broker forwards it unchanged.

## Event identity and emission

Event ids are deterministic. The collector derives an id from the device,
agent, session, event side, provider response identity, and a content digest,
so observing the same exchange again yields the same id and ingestion stays
idempotent. Distinct provider calls produce distinct ids. The content digest
covers the side's conversation entries before the content policy applies, so
the policy does not change an id: every entry's `role`, `text`, `call_id`,
`name`, and `item_id` in order, followed by the digests of the side's
attachments. `completeness`, the declared subagent and root turn ids, the
path, and the headers do not enter the id.

The broker emits events only for exchanges its Agent protocol parser accepted.
An exchange the parser rejects produces no event. Within an exchange that
produces events, a side produces one when its conversation has at least one
entry, even with empty text, when it carries an image, or when it has token
usage.

## Delivery

The official delivery plugin sends `observed_at`, `conversation`,
`response_id`, `previous_response_id`, `subagent_id`, `parent_subagent_id`, and
`turn_id` as top-level fields of the backend usage event, each as the event
carries it and absent where the event omits it, and sends `side` as the
top-level `event_type` (`request` or `response`). It stores the purpose as
`metadata.purpose`, the omitted categories as `metadata.omitted`, the path as
`metadata.path`, and the headers as `metadata.headers`. Backend
trajectories consume these fields without decoding provider bodies. Other plugins may translate the event for their own destinations.

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
