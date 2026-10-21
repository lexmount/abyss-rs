# OpenClaw and Hermes

The built-in `openclaw` and `hermes` harnesses reuse the Responses, Chat Completions,
and Anthropic Messages parsers. Responses WebSocket traffic is also supported.
They require a non-empty client-owned session ID before emitting events. Missing
session IDs are not replaced with a response ID, prompt-cache key, or connection ID.

Both are enabled by default, including with an older policy that has no entries
for them. Control them using `abyss config harness enable openclaw` or
`abyss config harness disable hermes`. Content controls follow the existing
per-harness policy format. A Codex backend URL identifies a protocol, not the
calling harness. OpenClaw/Hermes process identity or client request markers take
precedence over compatible Codex/Claude Code fingerprints; disabling the client
does not relabel its events.

## OpenClaw

OpenClaw's own OpenAI transport can send `x-openclaw-session-id` and
`metadata.openclaw_session_id`. The detector also accepts OpenClaw's own
User-Agent or `originator`. Per-request WebSocket metadata takes precedence over
the session in the upgrade headers.

The Codex route tested with OpenClaw 2026.5.7 uses Pi's transport instead: it sends
the real `session_id`, but identifies itself only as `pi` in HTTP headers. Abyss
uses the source process name or executable basename supplied by ingress to
identify `openclaw`, `openclaw-gateway`, or the `openclaw.mjs` / `openclaw.js`
entrypoint, including Windows `.exe` names. Session identity still comes from
the native request or WebSocket upgrade headers.

Process attribution follows the same ingress metadata contract as Codex and
Claude Code. The current explicit HTTP proxy ingress does not supply process
metadata; Pi requests without an OpenClaw marker cannot be attributed on that
ingress. Platform ingress can supply process identity, but a generic `node`
executable alone is insufficient. Abyss does not infer OpenClaw from a generic
Pi User-Agent, interpreter name, or parent directory.

`x-openclaw-turn-id` / `metadata.openclaw_turn_id` identify individual model calls,
including transport retry attempts. They are not copied to Abyss' user `turn_id`.
Events retain the provider's `response_id` and `previous_response_id` for downstream
grouping. Custom provider routes may omit these session markers and need client
instrumentation before their events can be attributed.

For routes carrying native OpenClaw request markers, explicit-proxy mode can be
used as follows. Set the proxy and CA on the process that makes model requests:

```bash
export NODE_EXTRA_CA_CERTS='/absolute/path/to/abyss-root-ca.pem'
abyss run -- openclaw agent --local --session-id <session-uuid> --message 'Hello'
```

For a persistent Gateway, launch the Gateway with those variables; setting them
only on a CLI that talks to an already-running Gateway does not affect its model
requests. The required OpenAI/Codex hosts are in the packaged interception policy.
Other providers need an explicit interception rule for their API hosts.

## Hermes

Hermes' native Codex route sends `session_id`. It identifies itself with
`HermesAgent/<version>` or `originator: hermes-agent`; its custom-backend
`codex_cli_rs/... (Hermes Agent)` compatibility identity is also recognized.
Ingress-supplied process names or executable basenames `hermes` and `hermes-agent`
are also recognized, including Windows `.exe` names. A generic Python process
does not identify Hermes. Process identity does not replace the session ID.

Hermes 0.22's ordinary OpenAI API route does not send a session header by default.
The included [Hermes plugin](../integrations/hermes/abyss) uses Hermes' supported
`llm_request` middleware to add:

* `x-hermes-session-id`: the current runtime session ID.
* `x-hermes-turn-id`: the runtime user turn ID, when available.

Install it from this checkout into the active Hermes home, preserving any existing
plugin of the same name:

```bash
mkdir -p "${HERMES_HOME:-$HOME/.hermes}/plugins/abyss"
cp -n integrations/hermes/abyss/{__init__.py,plugin.yaml} "${HERMES_HOME:-$HOME/.hermes}/plugins/abyss/"
hermes plugins doctor "${HERMES_HOME:-$HOME/.hermes}/plugins/abyss" --ci
hermes plugins enable abyss
abyss run -- hermes chat -q 'Hello' --oneshot
```

Restart an existing Hermes process after enabling the plugin. The plugin leaves
provider bodies, authentication, and other headers intact. Calls without runtime
session context are not assigned a synthetic session. In particular, auxiliary
calls that bypass this middleware need their own session marker. Static
`model.default_headers` cannot express a different real session for every run;
Hermes' `session_affinity_header` uses a routing/cache scope that may differ from
the physical session ID.

Hermes uses Python's HTTP client and CA handling. If the broker CA is not in the
client's trust store, configure `ssl_ca_cert` on the matching provider with a PEM
bundle containing that CA and the public roots required by the client. Merge this
example into `config.yaml` for the ordinary OpenAI route:

```yaml
providers:
  openai-api:
    base_url: https://api.openai.com/v1
    ssl_ca_cert: /absolute/path/to/combined-ca-bundle.pem
```

The installed Hermes 0.22 TLS resolver does not honor `SSL_CERT_FILE` as a custom
bundle on this path; the explicit provider setting was verified through the
proxy. Keep TLS verification enabled.

The request/session mapping is verified through the public Agent Hook boundary
in `crates/abyss-agent-hook/tests/client_sessions.rs`; plugin callback tests run
with `python3 -m unittest discover -s integrations/hermes -p 'test_*.py'` and `make test`.
