# Kimi with DSH

Abyss observes Kimi's Moonshot API through the shared OpenAI Responses,
Chat Completions, and Anthropic Messages parsers. Harness, provider, and model
remain independent: DSH requests to the China endpoint produce
`agent.name = "deepseek-harness"`, `llm.provider = "api.moonshot.cn"`, and the
actual requested model, such as `kimi-k3`. Compatible gateways retain their own
hostname as provider.

## Client configuration

Keep credentials in the client environment as `KIMI_API_KEY`. Abyss does not
need the key in its configuration. The following patch uses official DSH
`0.2.0-rc.2` with `kimi-k3`:

```json
[
  {
    "id": "agent-default-model",
    "config": {
      "provider": "kimi",
      "model": "kimi-k3",
      "reasoningEffort": "low"
    }
  },
  {
    "id": "llm-pi-ai",
    "config": {
      "providers": {
        "kimi": {
          "apiKeyEnv": "KIMI_API_KEY",
          "api": "openai-completions",
          "baseURL": "https://api.moonshot.cn/v1",
          "models": [
            {
              "id": "kimi-k3",
              "contextWindow": 1048576,
              "maxTokens": 2048,
              "reasoningEfforts": {"low": "low", "high": "high", "max": "max"}
            }
          ],
          "compat": {
            "thinkingFormat": "openai",
            "maxTokensField": "max_tokens",
            "supportsDeveloperRole": false
          }
        }
      }
    }
  }
]
```

Save as `kimi-patch.json`. Configure the
[Abyss CA and TLS policy](configuration.md), then launch the client:

```bash
export NODE_EXTRA_CA_CERTS='/absolute/path/to/abyss-root-ca.pem'
abyss run -- dsh --profile headless --patch /absolute/path/to/kimi-patch.json \
  --json 'Read probe.txt with the read tool and report its contents.'
abyss run -- dsh --profile web --patch /absolute/path/to/kimi-patch.json
abyss run -- dsh-tui --patch /absolute/path/to/kimi-patch.json
```

Use the endpoint associated with the key's account. The international endpoint
is `https://api.moonshot.ai/v1`. Existing Abyss policy files are preserved on
upgrade; add the Kimi host rule from the configuration guide when necessary.
Custom gateways need their own TLS rule.

For **Responses**, change `api` to `openai-responses` and remove `compat`.
The base URL remains `https://api.moonshot.cn/v1`, yielding `/v1/responses`.

For **Messages**, use DSH's native `llm-deepseek` adapter with a Kimi endpoint:

```json
[
  {
    "id": "agent-default-model",
    "config": {
      "provider": "deepseek-official",
      "model": "kimi-k3",
      "reasoningEffort": "low"
    }
  },
  {
    "id": "llm-deepseek",
    "config": {
      "apiKeyEnv": "KIMI_API_KEY",
      "baseURL": "https://api.moonshot.cn/anthropic",
      "maxTokens": 2048,
      "models": [
        {"id": "kimi-k3", "contextWindow": 1048576, "maxTokens": 2048}
      ]
    }
  }
]
```

`deepseek-official` selects the adapter's registered route; the configured URL
determines the provider. Both adapters belong to the official DeepSeek Harness
project. `llm-deepseek` uses Messages, while `llm-pi-ai` selects its wire API.

## Observed content and usage

Chat Completions carries thinking in `reasoning_content`, including assistant
history sent after a tool call. Responses carries reasoning items and summary
events; Messages carries `thinking` blocks. These produce the `reasoning`
conversation role. Tool calls, streamed arguments, tool results, and final text
use the existing normalized event structures. Content capture policy applies
to thinking as well as other conversation text.

OpenAI-compatible input totals include cache reads and writes. Abyss reads
`input_tokens_details` or `prompt_tokens_details`, accepts `cache_write_tokens`
alongside the existing `cache_creation_tokens` spelling, and falls back to
top-level `cached_tokens` for cache reads. Aliases are alternatives, never added
together; existing fields, including an explicit zero, retain precedence.
Normalized input excludes both cache counters:

```text
total_tokens = input_tokens + cache_read_tokens + cache_write_tokens + output_tokens
```

Native Messages already reports uncached input separately from
`cache_read_input_tokens` and `cache_creation_input_tokens`. Its
`output_tokens_details.thinking_tokens` and Responses'
`output_tokens_details.reasoning_tokens` are subsets of output, not additional
tokens. A missing reasoning counter does not mean there was no thinking text.

## Session attribution and regression

The session ID depends on what the client transmits. With the tested DSH version:

| API / adapter | Session identity | Abyss behavior |
| --- | --- | --- |
| Responses / `llm-pi-ai` | `session_id` header | Real DSH session |
| Chat Completions / `llm-pi-ai` | No session header on this route | Per-request `flow-*` fallback |
| Messages / `llm-deepseek` | `x-deepseek-harness-session-id` header | Real DSH session |

Abyss does not infer session identity from similar prompts or substitute model
response IDs for client sessions.

Credential-free regressions cover both official hosts and a gateway; JSON and
SSE in all three protocols; thinking history; a tool roundtrip; cache read/write
accounting; reasoning counters; and content capture disabled:

```bash
cargo test --locked -p abyss-agent-hook --test kimi
cargo test --locked -p abyss-broker --test broker_cli_blackbox kimi
```

Broker tests send fixtures through a real explicit proxy and assert plugin
socket events. Live verification additionally uses DSH headless, dsh-tui with
the DSH backend, and DSH Web UI through HTTPS interception and delivery into
the backend/dashboard.

Protocol references: [Chat Completions](https://platform.kimi.com/docs/api/chat),
[Responses](https://platform.kimi.com/docs/api/responses),
[Messages](https://platform.kimi.com/docs/api/messages).
