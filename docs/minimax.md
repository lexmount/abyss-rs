# MiniMax with DSH

Abyss observes MiniMax through Anthropic-compatible Messages, OpenAI-compatible
Chat Completions, and Responses. These use the shared protocol parsers; no model
allowlist or MiniMax credentials are required in the broker configuration.
The native `/v1/text/chatcompletion_v2` API is outside this integration.

Harness, provider, and model stay independent: DSH requests produce
`agent.name = "deepseek-harness"`, `llm.provider = "api.minimax.cn"`, and
`llm.model = "MiniMax-M3.1-Flash"`. International endpoints and custom gateways
retain their actual hostname as the provider.

## Client configuration

Use an endpoint matching the key's region. The current domestic root is
`https://api.minimax.cn`; the international root is `https://api.minimax.io`.
Keep the key in the client's `MINIMAX_API_KEY` environment variable. For example,
when the raw key is stored in a local file:

```bash
export MINIMAX_API_KEY="$(cat "$HOME/.minimax-api-keys/local.key")"
```

Save this patch as `minimax-patch.json`. It uses official DSH `0.2.0-rc.2`'s
Messages adapter with the domestic endpoint:

```json
[
  {
    "id": "agent-default-model",
    "config": {"provider": "deepseek-official", "model": "MiniMax-M3.1-Flash"}
  },
  {"id": "session-title-llm", "disabled": true},
  {"id": "session-telemetry-otel", "disabled": true},
  {
    "id": "llm-deepseek",
    "config": {
      "apiKeyEnv": "MINIMAX_API_KEY",
      "baseURL": "https://api.minimax.cn/anthropic",
      "maxTokens": 4096,
      "models": [
        {"id": "MiniMax-M3.1-Flash", "contextWindow": 128000, "maxTokens": 4096}
      ],
      "retryPolicy": {"mode": "normal", "maxRetries": 2}
    }
  }
]
```

`deepseek-official` names the DSH adapter, while `baseURL` selects MiniMax.
The context window above is a conservative client limit for this smoke test.

Configure the [Abyss CA and TLS policy](configuration.md), then launch:

```bash
export NODE_EXTRA_CA_CERTS='/absolute/path/to/abyss-root-ca.pem'
abyss run -- dsh --profile headless --patch /absolute/path/to/minimax-patch.json \
  --json 'Read probe.txt with the read tool and report its contents.'
```

For **Chat Completions**, change the default provider to `minimax` and replace
the `llm-deepseek` entry with:

```json
{
  "id": "llm-pi-ai",
  "config": {
    "providers": {
      "minimax": {
        "apiKeyEnv": "MINIMAX_API_KEY",
        "baseURL": "https://api.minimax.cn/v1",
        "api": "openai-completions",
        "models": [
          {"id": "MiniMax-M3.1-Flash", "contextWindow": 128000, "maxTokens": 4096}
        ],
        "compat": {"maxTokensField": "max_tokens", "supportsDeveloperRole": false}
      }
    }
  }
}
```

For **Responses**, use the same `/v1` base URL, change `api` to
`openai-responses`, and remove `compat`.

MiniMax-M3.1-Flash requires thinking; do not set thinking to disabled or reasoning
effort to `none`. Preserve complete assistant blocks and tool calls in multi-turn
history. The native adapters handle this in the tested configuration.

## Capture and session behavior

New CLI policies intercept `api.minimax.cn`, `api.minimax.io`, and the legacy
domestic API host `api.minimaxi.com`. Existing policies need the
[MiniMax TLS rule](configuration.md) added explicitly. The rule does not match
the MiniMax website or arbitrary subdomains. Compatible gateways need their own
explicit host rule.

The shared parsers preserve Chat Completions `reasoning_content`, Responses
`reasoning_text` content, and Messages `thinking` blocks as reasoning entries.
Cache reads are disjoint from uncached input; reasoning tokens are a subset of
output and do not inflate totals. Streamed tool arguments retain their call ID
so the following tool result can be correlated.

DSH `0.2.0-rc.2` sends its native session ID on Messages and Responses. Its pi
Chat Completions adapter does not transmit a session ID, so that route uses
the documented per-request `flow-*` fallback. Abyss does not infer a shared
session from matching prompts.

## Verification

Credential-free regressions exercise all three protocols in JSON and SSE,
domestic/international/legacy hosts and a gateway, thinking history, a tool
roundtrip, cache usage, and content capture disabled:

```bash
cargo test --locked -p abyss-agent-hook --test minimax
cargo test --locked -p abyss-broker --test broker_cli_blackbox minimax
cargo test --locked -p abyss-cli compatible_provider_interception
```

The broker regression forwards compressed requests and streams through a real
explicit proxy and verifies plugin socket events. Live verification on
2026-10-24 used DSH `0.2.0-rc.2`, `MiniMax-M3.1-Flash`, and `api.minimax.cn`
through HTTPS interception, the delivery plugin, and an isolated backend.
Messages, Chat Completions, and Responses all passed the existing matrix
verifier's tool roundtrip, final answer, identity, session, delivery health, and
exact input/output/cache-read usage checks. Native DSH traces do not expose
reasoning/cache-write counters, so those comparisons are unavailable rather
than assumed zero. Other model versions and regional keys were not live-tested.

Protocol references: [Messages](https://platform.minimax.io/docs/api-reference/text-anthropic-api),
[Chat Completions](https://platform.minimax.io/docs/api-reference/text-openai-api),
[Responses](https://platform.minimax.io/docs/api-reference/responses-create),
and [domestic endpoints](https://platform.minimax.cn/docs/api-reference/text-anthropic-api).
