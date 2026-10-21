# Hermes

The built-in `hermes` harness reuses the Responses, Chat Completions, and
Anthropic Messages parsers, including Responses WebSocket traffic. A non-empty
client-owned session ID is required; response IDs and cache keys cannot replace it.

Hermes is enabled by default, including with older policies. Use
`abyss config harness disable hermes` to disable it. A Codex backend URL identifies
a protocol, not the calling harness. Hermes process identity or request markers
take precedence over Codex/Claude Code compatibility fingerprints, even when
Hermes observation is disabled.

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
