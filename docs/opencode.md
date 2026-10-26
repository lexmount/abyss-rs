# OpenCode

The built-in `opencode` harness observes OpenCode provider requests using the
existing Chat Completions, Responses, and Anthropic Messages parsers. No OpenCode
plugin or source changes are required. The harness is enabled by default,
including with older policies; `abyss config harness disable opencode` disables
it and `abyss config harness enable opencode` enables it again.

## Native identity and correlation

| Header | Mapping |
| --- | --- |
| `User-Agent: opencode/<channel>/<version>/<client>` | Harness identity and version |
| `User-Agent: opencode/<version>` | Legacy identity and version |
| `x-opencode-session-id` | Native session ID |
| `x-opencode-session` | Session alias used by OpenCode gateways |
| `x-session-id` | Session fallback, accepted only with an OpenCode User-Agent |
| `x-opencode-request` | User message ID used as `turn_id`, when present |

The modern session header takes precedence over the two OpenCode aliases.
Other session sources keep their existing relative order; protocol-specific
headers such as `x-claude-code-session-id` can take precedence. Blank values are ignored;
requests without a usable session ID retain the protocol's existing fallback,
which does not guarantee correlation across user turns. Parent-session headers
do not replace the active session.

OpenCode 1.19.4 sends `x-opencode-request` on its own gateway requests, but omits
it for ordinary providers such as DeepSeek. Those requests retain an empty
`turn_id`; their native session ID and provider `response_id` still correlate
the conversation and individual inferences. Generic request IDs, cache affinity
keys, and session IDs are not used to invent user-turn IDs. Responses WebSocket
frames may inherit the upgrade's session, but not its user-turn header.

Gateway hostnames and OpenCode session headers alone do not identify the client.
Other SDK clients can use those gateways. OpenCode requests with an overridden
User-Agent or legacy gateway requests without its native User-Agent cannot be
identified by this detector. Headers provide attribution, not authenticated
process identity.

The native contract is defined by OpenCode's
[provider request builder](https://github.com/anomalyco/opencode/blob/v1.19.4/packages/opencode/src/session/llm/request.ts)
and [User-Agent construction](https://github.com/anomalyco/opencode/blob/v1.19.4/packages/opencode/src/installation/index.ts).

## Provider and proxy configuration

Configure a provider using OpenCode's [provider settings](https://opencode.ai/docs/providers/),
then run it through Abyss. For example, with DeepSeek credentials and a model
configured in OpenCode:

```bash
abyss run -- opencode run --model deepseek/deepseek-flash 'Hello'
```

Use OpenCode's `--session <session-id>` option to resume the same conversation
in another process. Credentials belong in OpenCode's credential storage or
environment, not in Abyss policies.

The provider hostname must be selected for TLS interception. New CLI policies
already include `api.deepseek.com`; custom gateways need their own host rule.
If the broker CA is outside OpenCode's trust store, pass its PEM file to the
client at startup:

```bash
NODE_EXTRA_CA_CERTS=/absolute/path/to/abyss-root-ca.pem \
  abyss run -- opencode run --model deepseek/deepseek-flash 'Hello'
```

## Validation

Live verification used OpenCode 1.19.4 and `deepseek-flash` through an isolated
explicit TLS proxy with `NODE_EXTRA_CA_CERTS`. A real file-read tool call, a
resumed conversation in a new process, and an independent conversation produced
four model requests and eight normalized request/response events. The official
delivery plugin uploaded all eight events to a local HTTP collector. Native
session IDs, tool calls/results, output tokens, and cache-read usage were
preserved; token totals matched OpenCode's own step results.

Automated coverage in `crates/abyss-agent-hook/tests/client_sessions.rs` checks
session aliases, declared turns, protocol variants, policy controls, and false
positives. `crates/abyss-broker/tests/scenarios/opencode.rs` exercises streaming
tools and resumed sessions through a real broker and plugin socket with a local
provider. Both run with `make test` and require no provider credentials.
