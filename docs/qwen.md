# Qwen with DSH

Abyss observes Qwen through Alibaba Cloud Model Studio's OpenAI-compatible
Responses and Chat Completions APIs and Anthropic-compatible Messages API.
The shared protocol parsers handle all three; the native DashScope generation
API is outside this integration.

Harness, provider, and model remain independent. For example, a DSH request
produces `agent.name = "deepseek-harness"`,
`llm.provider = "dashscope.aliyuncs.com"`, and `llm.model = "qwen3.8-flash"`.
Workspace endpoints and compatible gateways retain their own hostname.

## Client configuration

Keep the key in the client environment as `QWEN_API_KEY`; Abyss does not need
the key in its configuration. This patch uses official DSH `0.2.0-rc.2` and
`qwen3.8-flash` with a general Beijing-region Model Studio key:

```json
[
  {
    "id": "agent-default-model",
    "config": {
      "provider": "qwen",
      "model": "qwen3.8-flash",
      "reasoningEffort": "low"
    }
  },
  {
    "id": "llm-pi-ai",
    "config": {
      "providers": {
        "qwen": {
          "apiKeyEnv": "QWEN_API_KEY",
          "api": "openai-completions",
          "baseURL": "https://dashscope.aliyuncs.com/compatible-mode/v1",
          "models": [
            {
              "id": "qwen3.8-flash",
              "contextWindow": 1048576,
              "maxTokens": 2048,
              "reasoningEfforts": {"low": "low"}
            }
          ],
          "compat": {
            "thinkingFormat": "qwen",
            "maxTokensField": "max_tokens",
            "supportsDeveloperRole": false
          }
        }
      }
    }
  }
]
```

Save as `qwen-patch.json`. Configure the
[Abyss CA and TLS policy](configuration.md), then launch:

```bash
export NODE_EXTRA_CA_CERTS='/absolute/path/to/abyss-root-ca.pem'
abyss run -- dsh --profile headless --patch /absolute/path/to/qwen-patch.json \
  --json 'Read probe.txt with the read tool and report its contents.'
abyss run -- dsh --profile web --patch /absolute/path/to/qwen-patch.json
abyss run -- dsh-tui --patch /absolute/path/to/qwen-patch.json
```

For **Responses**, change `api` to `openai-responses` and remove `compat`.
The same base URL yields `/compatible-mode/v1/responses`.

For **Messages**, use the official `llm-deepseek` adapter with a Qwen endpoint:

```json
[
  {
    "id": "agent-default-model",
    "config": {
      "provider": "deepseek-official",
      "model": "qwen3.8-flash",
      "reasoningEffort": "low"
    }
  },
  {
    "id": "llm-deepseek",
    "config": {
      "apiKeyEnv": "QWEN_API_KEY",
      "baseURL": "https://dashscope.aliyuncs.com/apps/anthropic",
      "maxTokens": 2048,
      "models": [
        {"id": "qwen3.8-flash", "contextWindow": 1048576, "maxTokens": 2048}
      ]
    }
  }
]
```

`deepseek-official` selects this adapter's registered route; the configured URL
determines the provider. Both `llm-deepseek` and `llm-pi-ai` belong to the
official DeepSeek Harness project.

Select an endpoint matching the key's region and account type.
[Workspace endpoints](https://help.aliyun.com/zh/model-studio/qwen-api-via-openai-responses)
use `https://{WorkspaceId}.{region}.maas.aliyuncs.com` with the same paths.
The documented legacy regional hosts remain supported. Coding Plan uses
separate keys and endpoints, such as `https://coding.dashscope.aliyuncs.com/v1`
and `https://coding.dashscope.aliyuncs.com/apps/anthropic`; these credentials
are not interchangeable with general Model Studio keys.
See the [Coding Plan documentation](https://help.aliyun.com/zh/model-studio/coding-plan).
Live verification here uses the general Beijing endpoint, not Coding Plan.

## Observed content and usage

Chat Completions `reasoning_content`, Responses reasoning events/items, and
Messages `thinking` blocks map to the `reasoning` conversation role.
Responses can send `response.reasoning_text.delta` while its final reasoning
item contains `summary`; the snapshot reconciles the streamed text.

Chat Completions argument-only deltas may carry an empty tool `id`. The parser
preserves the previously received nonempty ID and name while assembling the
arguments, so the next request's tool result still matches the call.

Messages can correct its provisional `message_start` usage in `message_delta`,
including reducing input tokens after cache accounting. The parser keeps the
latest reported counter, preserves omitted counters, and accepts explicit zero
corrections. It merges partial usage before partitioning compatible input totals.

OpenAI-compatible input includes cached tokens; native Messages reports
uncached input separately from its cache counters. Normalized usage follows:

```text
total_tokens = input_tokens + cache_read_tokens + cache_write_tokens + output_tokens
```

Reasoning tokens are a subset of output, not an additional contribution to the
total. A missing reasoning counter does not mean no thinking text was returned.

## Session attribution and regression

With the tested DSH version, Responses sends `session_id` and native Messages
sends `x-deepseek-harness-session-id`; both retain the real DSH session.
The pi Chat Completions route sends neither, so Abyss uses a per-request
`flow-*` fallback. Model response IDs are not substituted for client sessions.

Credential-free JSON/SSE fixtures cover the three protocols, reasoning,
tool roundtrips, empty tool metadata, corrected cumulative usage, cache
accounting, provider attribution, and content capture disabled:

```bash
cargo test --locked -p abyss-agent-hook --test qwen
cargo test --locked -p abyss-broker --test broker_cli_blackbox qwen
```

Broker tests exercise a real explicit proxy and plugin socket. Live verification
uses DSH headless, dsh-tui with the DSH backend, and DSH Web UI through HTTPS
interception, delivery, backend storage, and dashboard display.

Protocol references:
[Chat Completions](https://help.aliyun.com/zh/model-studio/qwen-api-via-openai-chat-completions),
[Responses](https://help.aliyun.com/zh/model-studio/qwen-api-via-openai-responses),
[Messages](https://help.aliyun.com/zh/model-studio/anthropic-api-messages).
