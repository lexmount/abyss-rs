# GLM with DSH

Abyss observes GLM through the shared Chat Completions, Responses, and Anthropic
Messages parsers.
Harness identity comes from the client, provider identity comes from the API
hostname, and model identity comes from the request or response. For example,
DSH using GLM produces `agent.name = "deepseek-harness"`,
`llm.provider = "open.bigmodel.cn"`, and `llm.model = "glm-4.7"`.

Chat Completions parsing supports JSON and SSE responses, assistant
`reasoning_content` (including preserved request history), streamed tool arguments, tool results,
`prompt_tokens_details.cached_tokens`, and
`completion_tokens_details.reasoning_tokens`. Thinking has the `reasoning`
conversation role. Cached input is separate from uncached input; reasoning
tokens are a subset of output tokens and are not added to the total twice.
The normalized content policy also applies to thinking.

## Client configuration

Configure the API key and model in DSH. Abyss does not need provider credentials
in any configuration file. The following patch was tested with DSH
`0.2.0-rc.2`, its `llm-pi-ai` adapter, and dsh-tui `0.16.1` using the DSH backend.
Save it as `glm-patch.json` and set `GLM_API_KEY` in the client environment:

```json
[
  {
    "id": "agent-default-model",
    "config": {
      "provider": "glm",
      "model": "glm-4.7",
      "reasoningEffort": "low"
    }
  },
  {
    "id": "llm-pi-ai",
    "config": {
      "providers": {
        "glm": {
          "apiKeyEnv": "GLM_API_KEY",
          "api": "openai-completions",
          "baseURL": "https://open.bigmodel.cn/api/paas/v4",
          "models": [
            {
              "id": "glm-4.7",
              "contextWindow": 200000,
              "maxTokens": 2048,
              "reasoningEfforts": {"off": null, "low": "low"}
            }
          ],
          "compat": {
            "thinkingFormat": "zai",
            "maxTokensField": "max_tokens"
          }
        }
      }
    }
  }
]
```

Use the endpoint associated with your account: the standard base URLs are
`https://open.bigmodel.cn/api/paas/v4` and `https://api.z.ai/api/paas/v4`.
Coding Plan accounts use `/api/coding/paas/v4` on the corresponding host.
These append `/chat/completions` on the wire. The same parser also handles
compatible gateways; the provider field retains the actual gateway hostname.

Configure the [Abyss CA and TLS policy](configuration.md) before starting DSH:

```bash
export NODE_EXTRA_CA_CERTS='/absolute/path/to/abyss-root-ca.pem'
abyss run -- dsh --profile headless --patch /absolute/path/to/glm-patch.json \
  --json 'Read probe.txt with the file reading tool and report its contents.'
abyss run -- dsh-tui --patch /absolute/path/to/glm-patch.json
```

If dsh-tui's first-run guide asks for `DEEPSEEK_API_KEY`, press Esc to skip
that guide when using this GLM configuration. The model indicator should show
`glm-4.7`; its credential comes from `GLM_API_KEY`.

Existing runtime policies are preserved on upgrade. Add the GLM host rule from
the configuration guide if it is missing. Model selection, limits, and
credentials remain client-owned.

## Event attribution and verification

When supplied, `x-deepseek-harness-session-id` is accepted after the existing
OpenAI session headers and metadata. Session correlation depends on which DSH
adapter sends the request. Live checks with DSH `0.2.0-rc.2` and `glm-4.7`
produced the following results:

| API / adapter | Session sent by DSH | Abyss session |
| --- | --- | --- |
| Chat Completions / `llm-pi-ai` | None | `flow-*` request fallback |
| Responses / `llm-pi-ai` | `session_id` header | Actual DSH session ID |
| Messages / `llm-pi-ai` | None | `anthropic-unattributed-open-bigmodel-cn` |
| Messages / native `llm-deepseek` | `x-deepseek-harness-session-id` | Actual DSH session ID |

An unattributed ID cannot reliably distinguish separate DSH sessions. Abyss
does not infer a session from conversation text.

For [Responses](https://docs.bigmodel.cn/cn/guide/develop/responses/introduction),
change the pi provider's `api` to `openai-responses`, change `baseURL` to
`https://open.bigmodel.cn/api/v1`, and remove the Chat Completions `compat`
object. This calls `/api/v1/responses`. The parser captures
`response.reasoning_text.delta` / `.done` and `reasoning_text` content alongside
the existing reasoning summary events, including streams without `[DONE]`.

For [Messages](https://docs.bigmodel.cn/cn/guide/develop/claude/introduction),
the pi provider uses `api: "anthropic-messages"` and
`baseURL: "https://open.bigmodel.cn/api/anthropic"` without the Chat Completions
`compat` object. To retain the real DSH session ID, the native Messages adapter
was also verified with this patch:

```json
[
  {
    "id": "agent-default-model",
    "config": {
      "provider": "deepseek-official",
      "model": "glm-4.7",
      "reasoningEffort": "low"
    }
  },
  {
    "id": "llm-deepseek",
    "config": {
      "apiKeyEnv": "GLM_API_KEY",
      "baseURL": "https://open.bigmodel.cn/api/anthropic",
      "maxTokens": 2048,
      "models": [{"id": "glm-4.7", "contextWindow": 200000, "maxTokens": 2048}]
    }
  }
]
```

Here `deepseek-official` selects DSH's adapter; its configured endpoint sends
requests to GLM, and Abyss records the actual provider as `open.bigmodel.cn`.
In the tested DSH version, this native adapter is the default route; pi provider
routes require explicit configuration. The native adapter can change API
endpoints, credentials, and models, while retaining the Messages protocol and
its registered provider name. Responses and Chat Completions use the pi adapter
in these examples.
Both APIs completed a real file tool call, tool-result followup, and final
answer through the broker and delivery plugin into the local backend.

The deterministic regressions require no API key:

```bash
cargo test --locked -p abyss-agent-hook --test glm
cargo test --locked -p abyss-broker --test broker_cli_blackbox glm
```

The first test covers both official hosts, a gateway, Chat Completions paths,
Responses reasoning events, streaming and JSON, tool followups, usage accounting,
and disabled content capture. The second sends GLM fixtures through a real
explicit broker and asserts the resulting plugin socket events. Live DSH verification additionally
exercises HTTPS interception and the actual provider response.
