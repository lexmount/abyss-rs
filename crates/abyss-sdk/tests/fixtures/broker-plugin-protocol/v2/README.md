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

V2 removes `turn_index`. The collector keeps no turn state. `turn_id` names
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

`session_title` is the title from the response side of a `session_title` call,
read only when the reply is a single `{"title": "…"}` object. It names the
event's own session. Like `text`, it is model output and is omitted when the
content policy drops conversation text.

Codex names a task from a separate thread whose requests do not say which
session they name, so Codex events carry neither field; its naming threads
carry `naming_thread` instead.

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

The official delivery plugin sends `turn_id`, `naming_thread`, `stream_id`,
`response_id`, and `previous_response_id` as top-level fields of the usage
event.

New Rust clients negotiate v2. The broker continues accepting v1 clients and
omits `naming_thread`, `stream_id`, `response_id`, `previous_response_id`,
`conversation`, `purpose`, and `session_title` for them.
Existing Python and TypeScript v1 clients keep the unchanged v1 contract. The
v1 schema remains unchanged apart from its optional `turn_id`, which carries
the same value as in v2. Upgrade the backend first, then the broker, then the
delivery client.

Previously stored records keep their metadata unchanged and no automatic
database rewrite occurs. Producing role-aware projections for records stored
before v2 requires an explicit offline conversion.

The 64 MiB JSON frame limit applies to v2 frames. Framing and control messages
otherwise follow [v1](../v1/README.md).
