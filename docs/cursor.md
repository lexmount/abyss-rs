# Cursor Local

The built-in `cursor` harness observes provider requests from Cursor Local /
Private Inference (`agent-local` or `cursor-agent-local`). It reuses the HTTP
Chat Completions, Responses, and Anthropic Messages parsers.

The ordinary `agent` / `cursor-agent` CLI calls Cursor's cloud services using
Connect RPC and Protobuf. That protocol is not supported by this integration.
Its `--api-key` and `--endpoint` configure Cursor authentication and services,
not an OpenAI-compatible provider. Do not pass a provider key as a Cursor key.

## Native identity and correlation

Cursor Local sends these provider request headers:

| Header | Meaning |
| --- | --- |
| `User-Agent: Cursor-CLI/<version> ...` | Harness identity and version |
| `X-Agent-Id` | Conversation ID, matching the CLI's `session_id` |
| `X-Request-Id` | User generation ID, matching the CLI result's `request_id` |

The generation ID stays the same across model calls before and after local tool
execution, and changes for the next user turn. Each provider response retains
its own `response_id`. No custom identification headers or client plugin are
required.

Session extraction remains in the existing protocol parsers. `X-Agent-Id` is
accepted as a session only with the native `Cursor-CLI/` User-Agent; existing
session fields retain precedence. Missing or blank values retain the existing
protocol fallback. A generic `X-Request-Id` from another harness is not treated
as a Cursor turn.

The harness is enabled by default, including with older policies. Use
`abyss config harness disable cursor` to disable observation.

## Provider and proxy configuration

Configure the Local CLI's provider with `CURSOR_LOCAL_AGENT_BASE_URL` and
`CURSOR_LOCAL_AGENT_API_KEY`, then run it through Abyss:

```bash
abyss run -- agent-local --authless --model <provider-model-id> -p 'Hello'
```

Use `--resume <session_id>` to continue the same conversation in a new process.
Provider credentials belong in the child process environment or the client's
credential configuration, not in Abyss policies.

On macOS, the `2026.10.19-6bbf2c4` launchers for both ordinary and Local CLIs
enable Node's `--use-system-ca` by default. The Local CLI was verified against
DeepSeek through an explicit TLS proxy using an already trusted system CA,
without `NODE_EXTRA_CA_CERTS` or disabled certificate verification. Ordinary CLI
model discovery accepted that CA and rejected an untrusted control CA.
`AGENT_CLI_CREDENTIAL_STORE=file` makes these launchers skip the system-CA flag;
do not assume that mode has the same trust behavior. For a CA outside the
client's trust store, configure `NODE_EXTRA_CA_CERTS` with the CA PEM.

The public hook regression cases in
`crates/abyss-agent-hook/tests/client_sessions.rs` cover protocol correlation,
multiple inferences in one turn, resumed turns, independent sessions, policy
disablement, and generic headers from other clients. Live wire verification used
Cursor Local `2026.10.19-6bbf2c4` with DeepSeek Chat Completions.
