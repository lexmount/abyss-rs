# Headless harness × model CI

`.github/workflows/agent-model-matrix.yml` runs real Codex CLI, Claude Code
`--print`, and DSH headless clients through the current checkout's broker and
delivery plugin into a fresh, digest-pinned Backend and PostgreSQL. It shares
`scripts.agent_e2e_ci`'s stack lifecycle and subprocess handling.

The default matrix has **32 cells, 16 harness/provider combinations, and 25
harness/provider/protocol routes**. Each model in a route is tested separately.

| Provider | Default models | Codex CLI | Claude Code | DSH headless |
| --- | --- | --- | --- | --- |
| OpenAI | `gpt-5`, `gpt-5.3-codex` | Responses, both models | Not a native Messages service | Responses, both models; Chat Completions, `gpt-5` |
| Anthropic | `claude-sonnet-5` | Not a native Responses service | Messages | Messages |
| DeepSeek | `deepseek-flash`, `deepseek-v4-pro` | Responses, both models | Messages, both models | Responses, Chat Completions, Messages; both models |
| GLM | `glm-4.7` | Responses | Messages | All three protocols |
| Kimi | `kimi-k3` | Responses | Messages | All three protocols |
| Qwen | `qwen3.8-flash` | Responses | Messages | All three protocols |

There are 7 Codex, 6 Claude Code, and 19 DSH cells. Desktop, TUI and Web UI
clients are excluded. This tests the actual clients, not hand-written API
requests bearing spoofed harness headers. Incompatible direct combinations are
not scheduled; the matrix does not install a protocol-converting gateway.
DeepSeek's [Responses API](https://api-docs.deepseek.com/guides/responses_api/)
explicitly supports Codex. Other provider paths follow the repository's
[GLM](../../docs/glm.md), [Kimi](../../docs/kimi.md), and
[Qwen](../../docs/qwen.md) integrations.

## GitHub configuration

Set these **repository Actions Secrets** (Settings → Secrets and variables →
Actions → Secrets). API key values are raw keys, without `Bearer `:

| Secret | Credential |
| --- | --- |
| `CODEX_API_KEY` | OpenAI API key; also used by the existing randomized Codex CI |
| `CLAUDE_CODE_API_KEY` | Anthropic API key, or the Messages gateway key when overriding its endpoint |
| `CLAUDE_CODE_BASE_URL` | Optional Anthropic Messages API root; reuses the existing Claude Code relay configuration |
| `ABYSS_E2E_DEEPSEEK_API_KEY` | DeepSeek API key |
| `ABYSS_E2E_GLM_API_KEY` | GLM general API key for `open.bigmodel.cn` |
| `ABYSS_E2E_KIMI_API_KEY` | Moonshot API key for `api.moonshot.cn` |
| `ABYSS_E2E_QWEN_API_KEY` | General Beijing-region Model Studio key for `dashscope.aliyuncs.com` |

`CODEX_API_KEY`, `CLAUDE_CODE_API_KEY`, and `CLAUDE_CODE_BASE_URL` reuse the
existing black-box workflows' Secrets. No additional OpenAI or Anthropic key
Secrets are needed. The relay URL applies to both Claude Code and DSH's
Anthropic cells. It is read only at run time and takes precedence over the
Anthropic `ABYSS_E2E_ENDPOINTS` override; when empty, the configured public
endpoint (or `https://api.anthropic.com` by default) is used. Planning and
aggregation do not receive this Secret. The uploaded case retains the public
plan identity, records `endpoint_source: CLAUDE_CODE_BASE_URL`, and redacts the
runtime relay URL/hostname. Provider assertions use the actual relay hostname.

Each cell receives **only its selected provider's secret**, only in the run
step (plus the relay URL for Anthropic cells). The API key is passed to the
client environment, never command-line arguments,
client configuration files, or workflow outputs. Uploads contain sanitized
comparison evidence only; raw service logs and CA/private configuration stay
outside `artifacts/`. Missing credentials fail with the exact secret name and
produce a failure artifact. They are never treated as successful skips.

The default model list is explicit so model retirement/access changes produce
an actionable failure. To expand or replace models without editing code, set
the optional **repository Variable** `ABYSS_E2E_MODELS` to a JSON object:

```json
{
  "anthropic": {"messages": ["claude-sonnet-5", "claude-opus-5-5"]},
  "openai": {"responses": ["gpt-5.3-codex"], "chat": ["gpt-5"]}
}
```

Keys are provider names and `responses`, `chat`, or `messages`. Each supplied
list replaces that route's defaults and expands every compatible harness.
Empty lists, duplicates, unsupported routes, malformed model names and matrices
larger than GitHub's 256-cell limit fail planning.

Set the optional **repository Variable** `ABYSS_E2E_ENDPOINTS` for regional
services, Coding Plans, or compatible relays. Values are HTTPS API roots
without `/responses`, `/chat/completions`, or `/messages` operation suffixes:

```json
{
  "anthropic": {"messages": "https://relay.example/anthropic"},
  "kimi": {
    "responses": "https://api.moonshot.ai/v1",
    "chat": "https://api.moonshot.ai/v1",
    "messages": "https://api.moonshot.ai/anthropic"
  }
}
```

Use a key valid for every configured route of that provider. A Coding Plan key
may not cover all three APIs; do not point a general API route at a Coding Plan
credential. URLs containing credentials, query strings, or fragments are
rejected. A relay retains its hostname as the expected event provider.

## Execution and assertions

Each disposable workspace contains an unpredictable verification code **not
included in the prompt**. The client must read it using a real tool and return
it with the audit marker. Every cell asserts:

- native process success, completed turn, tool output, and final answer;
- backend harness/provider/model identity and unique event IDs;
- captured tool call/result IDs match, including native IDs where exposed;
- captured tool output and assistant answer contain the hidden code;
- complete conversation capture, healthy services, and empty delivery spool;
- exact token totals against the native CLI trace, including available cache
  and reasoning counters; unavailable counters are explicitly listed;
- native session attribution, or DSH pi Chat Completions' documented per-request
  `flow-*` fallback. Response IDs are never substituted for session IDs.

Claude uses completed streaming message usage, including later downward
corrections, rather than provisional assistant snapshots. DSH sums `step_end`
usage. Codex uses `turn.completed`. Input comparisons include cached tokens;
reasoning tokens are a subset of output. Only explicitly marked prewarm events
are excluded. No mismatched auxiliary requests are silently subtracted.

The existing randomized Codex A/B/judge workflow remains the deeper visual and
multi-tool test. This matrix supplements it with a deterministic, common task
that also works for text-only models, without requiring an extra judge API call
for each cell. Both workflows use API keys in GitHub, not a runner subscription
login. Local legacy Codex runs without the key environment retain login support.

The workflow runs on same-repository PRs and manual dispatch. Manual inputs
filter harness, provider, protocol, or exact model; unmatched filters fail.
`fail-fast: false` preserves remaining results, with concurrency capped at eight.
The final aggregation requires an artifact and PASS from **every planned cell**;
missing artifacts, failed clients, 429s, unavailable models, and mismatches all
fail. The `skip-agent-e2e` label records a deliberate whole-matrix skip. Forks
run credential-free contracts on GitHub-hosted runners and never start the
live matrix jobs.

## Runner and local use

All jobs run on GitHub-hosted `ubuntu-latest` runners. Each live cell uses a
fresh VM with Docker, OpenSSL and Python; the workflow sets up stable Rust
through the repository's shared action and restores cached Cargo build outputs.
The matrix and randomized Codex E2E jobs share the `agent-e2e` Rust cache key.
The workflow selects Node.js 24 and installs only the cell's client into
its temporary job directory: Codex `0.163.0`, Claude Code `2.1.206`, or DSH
`0.2.0-rc.2`. Installation receives no API secrets. Local runs use preinstalled
clients, Docker, Cargo/Rust, OpenSSL and Python 3.10+. Required CLI capabilities
are checked and actual versions recorded;
the job does not modify global client installations, login, CA trust or user config.
DSH uses a fresh `DSH_HOME`; Codex ignores user rules/config; Claude uses bare
mode with settings sources disabled.

Codex jobs install Ubuntu's `bubblewrap` package and load its distribution
`bwrap-userns-restrict` AppArmor profile, as described in the
[Codex sandbox prerequisites](https://learn.chatgpt.com/docs/sandboxing#prerequisites).
This permits bubblewrap's namespace setup while keeping Codex's filesystem and
network sandbox enabled. A credential-free `codex sandbox` probe checks file
reads, denied read-only writes, and workspace writes before any model traffic.
Local Linux runs need the same bubblewrap/AppArmor prerequisites.

```bash
python3 -m scripts.agent_matrix_ci plan
python3 -m scripts.agent_matrix_ci plan --harness codex --provider deepseek
python3 -m unittest discover -s scripts/tests -p 'test_agent_*py'
python3 -m ruff check scripts/agent_matrix_ci scripts/tests/test_agent_matrix_ci.py
python3 -m ruff format --check scripts/agent_matrix_ci scripts/tests/test_agent_matrix_ci.py
```

For a real local run, select an `id` from `plan`, provide the corresponding raw
key in `ABYSS_MATRIX_API_KEY`, and run:

```bash
python3 -m scripts.agent_matrix_ci run --case '<planned-id>'
```

`ABYSS_AGENT_E2E_RUNTIME_ROOT` can select a fresh directory. Existing directories
are rejected. Each cell owns distinct ports, processes, Docker resources and
temporary certificates; cleanup runs on success, failure and SIGTERM. Evidence
is retained at `<runtime-root>/artifacts/result.json`. Linux and macOS can run
the same local command; GitHub uses Linux.
