# Structured Agent conversations (v2)

Version 2 adds `conversation` to Agent events, a structured and role-aware
projection built by the collector. Consumers read messages directly and never
decode provider transport bodies. V2 carries no raw provider content: no
transport bytes, decoded provider documents, or original content blocks.

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

`previous_response_id` is the provider continuation reference; its absence does
not invent an identity. `thread_source` is the source the agent declared, such
as `user` or `thread_title`. `instructions_present` reports whether the request
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

V2 removes `turn_index`. In v1 it was a counter the collector kept per
session in memory, restarted with the broker, and could not say which turn a
request belonged to. The collector now keeps no turn state; `turn_id` carries
the turn identity found in the traffic and consumers number turns:

- the Agent's own turn identity when it exposes one, such as the Codex turn id
  or Claude Code's `cc_turn:<cc_turn_index>`;
- otherwise absent, including other Anthropic clients and Claude Code subagent
  and side requests (see below). A provider call identity is never substituted
  for a turn, so `turn_id` always names a turn and never a single call.

The broker still sends v1 connections their required `turn_index`, fixed at
`1`; it no longer carries meaning.

## Claude request context

Two optional fields carry Anthropic Messages request context verbatim:

- `claude_code_billing` holds every `key=value` pair of the billing header
  Claude Code writes as the first line of its first system block
  (`x-anthropic-billing-header: cc_version=…; cc_turn_index=13;`). Values are
  the verbatim strings, including numbers and booleans. A request with the
  header but no pairs carries an empty object.
- `claude_thread` is the request `thread` object, such as `{"type": "create"}`
  or `{"type": "continue", "previous_message_id": "msg_…"}`.

For Claude Code, `turn_id` is `cc_turn:<cc_turn_index>` when the billing header
has a turn index; the index is stable across `continue` requests and the
`create` replay of one user turn. Claude Code requests without a turn index
(subagents, side requests, quota probes) carry no `turn_id`, so consumers place
them by their own rules.

The official delivery plugin stores both fields under the same names in the
usage-event metadata. The broker removes them for v1 connections.

## Call purpose and session title

`purpose` states what the Agent made a provider call for, when its traffic
says so. Both events of the call carry it. The only value is `session_title`:
the Agent asks the model to name the session the call belongs to.
Claude Code makes such a call with the naming instruction in its system prompt
(`You are naming a coding session…`) and the billing header present.

`session_title` is the title from the response side of a `session_title` call,
read only when the reply is a single `{"title": "…"}` object. It names the
event's own session. Like `text`, it is model output and is omitted when the
content policy drops conversation text.

Codex names a task from a separate thread whose requests do not say which
session they name, so Codex events carry neither field; its naming threads
remain visible through `conversation.thread_source`.

The official delivery plugin stores both fields under the same names in the
usage-event metadata. The broker removes them for v1 connections.

## Event identity and emission

Event ids are deterministic. The collector derives an id from the device,
agent, session, event side, provider response identity, and a content digest,
so observing the same exchange again yields the same id and ingestion stays
idempotent. Distinct provider calls produce distinct ids.

The broker emits events only for exchanges its Agent protocol parser accepted.
An exchange the parser rejects produces no event.

## Delivery and compatibility

The official delivery plugin stores the object as `metadata.conversation`.
Backend titles and trajectories consume these messages without decoding
provider bodies.

New Rust clients negotiate v2. The broker continues accepting v1 clients and
omits `conversation`, `claude_code_billing`, `claude_thread`, `purpose`, and
`session_title` for them.
Existing Python and TypeScript v1 clients keep the unchanged v1 contract. The
v1 schema remains unchanged apart from its optional `turn_id`. Upgrade the
backend first, then the broker, then the delivery client.

Previously stored records keep their metadata unchanged and no automatic
database rewrite occurs. Producing role-aware projections for records stored
before v2 requires an explicit offline conversion.

The 64 MiB JSON frame limit applies to v2 frames. Framing and control messages
otherwise follow [v1](../v1/README.md).
