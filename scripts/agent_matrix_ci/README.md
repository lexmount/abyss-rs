# Headless harness × model CI

Four independent Actions workflows run real Codex CLI, Claude Code `--print`,
DSH headless, and Hermes CLI clients through the current checkout's broker and
delivery plugin into a fresh, digest-pinned Backend and PostgreSQL. They share
`scripts.agent_e2e_ci`'s stack lifecycle and subprocess handling.

| Workflow | Default cells |
| --- | ---: |
| [Codex Model Matrix](../../.github/workflows/codex-model-matrix.yml) | 7 |
| [Claude Code Model Matrix](../../.github/workflows/claude-code-model-matrix.yml) | 6 |
| [DSH Model Matrix](../../.github/workflows/dsh-model-matrix.yml) | 19 |
| [Hermes Model Matrix](../../.github/workflows/hermes-model-matrix.yml) | 19 |

Each group has its own run, per-cell checks, artifacts and required aggregation.
Select the harness's workflow in Actions to inspect or rerun only that group.
All four call [the shared execution workflow](../../.github/workflows/agent-model-matrix.yml)
so client installation, assertions and credential handling stay consistent.

Automatic PR runs are limited to `abyss-broker` and its transitive workspace
dependencies: `abyss-agent-hook`, `abyss-mitm`, `abyss-plugin-protocol`, and
`abyss-storage`.
Changes anywhere in those crate directories, the root `Cargo.toml`/`Cargo.lock`,
`.cargo/`, or `rust-toolchain`/`rust-toolchain.toml` trigger all four groups.
Keep the four entry workflows' path filters aligned when the dependency graph
changes. Unrelated changes (including CLI-only crates, top-level docs,
TypeScript/Python SDKs, integrations, and CI scripts/workflows alone) do not start
the matrix. Use manual dispatch to validate matrix or integration changes
outside these paths. [PR path filters](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#git-diff-comparisons)
evaluate the entire PR diff, not just its latest commit.

**Only one live CI job per provider runs at a time across the repository.**
All matrix cells share `abyss-e2e-provider-<provider>` concurrency groups across
harnesses, protocols, models, PRs and manual runs. The existing Codex black-box
and randomized E2E jobs share the `openai` group; Claude Code black-box shares
the `anthropic` group. Different providers can still run in parallel. There is
no additional per-harness limit: waiting on one provider must not consume a
harness's slots and delay unrelated providers. These groups use the catalog
provider name even when an endpoint is overridden.

Provider locks use [GitHub Actions `queue: max`](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)
with `cancel-in-progress: false`. This allows up to 100 waiting jobs per provider;
the default single pending slot would discard waiting matrix cells. Queue
overflow fails/cancels excess jobs rather than treating them as passing. The
existing workflow-level cancellation still supersedes older commits on the
same PR. Serialization controls CI job overlap; it does not retry or hide
provider errors, or coordinate callers outside this repository's workflows.

The default matrix has **51 cells, 22 harness/provider combinations, and 40
harness/provider/protocol routes**. Each model in a route is tested separately.

| Provider | Default models | Codex CLI | Claude Code | DSH headless / Hermes CLI |
| --- | --- | --- | --- | --- |
| OpenAI | `gpt-5`, `gpt-5.3-codex` | Responses, both models | Not a native Messages service | Responses, both models; Chat Completions, `gpt-5` |
| Anthropic | `claude-sonnet-5` | Not a native Responses service | Messages | Messages |
| DeepSeek | `deepseek-flash`, `deepseek-v4-pro` | Responses, both models | Messages, both models | Responses, Chat Completions, Messages; both models |
| GLM | `glm-4.7` | Responses | Messages | All three protocols |
| Kimi | `kimi-k3` | Responses | Messages | All three protocols |
| Qwen | `qwen3.8-flash` | Responses | Messages | All three protocols |

There are 7 Codex, 6 Claude Code, 19 DSH, and 19 Hermes cells. Desktop, TUI and Web UI
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
Secrets are needed. The relay URL applies to Claude Code, DSH, and Hermes
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

Hermes cells run **three separate user turns** using `hermes chat --oneshot`
and native `--resume`, with machine-readable `--format stream-json` output.
The first turn reads the hidden code. The fixture is moved outside the workspace
before turns two and three, which must recall the code and marker from history
without tools. Both native replies and backend response events must contain them,
and all events must share the real Hermes session with exactly three backend
turns. Repeated request history is retained; this test does not change deduplication.

The checkout's [Hermes plugin](../../integrations/hermes/abyss) is installed in
each cell's isolated `HERMES_HOME`; it declares real runtime session/user-turn IDs
through Hermes' supported middleware. The provider's `api_mode` is explicitly
set to `chat_completions`, `codex_responses`, or `anthropic_messages`. OpenAI Chat
uses `reasoning=none` for tool compatibility; OpenAI/Messages is not scheduled.
Hermes' final JSONL result contains that process's usage, including uncached
input and separate cache read/write counters. Each resumed CLI is a new process;
the verifier sums the three results after adding caches back to inclusive input.
The result format does not expose reasoning-token counts, so they remain unavailable.

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

All four workflows run on matching same-repository PRs and manual dispatch.
Select the harness's workflow, then optionally filter provider, protocol or
exact model; unmatched filters fail. `fail-fast: false` preserves remaining results. The
repository-wide limit is one job per provider. With six configured providers,
at most six live provider jobs can execute simultaneously.
Each group's final aggregation requires an artifact and PASS from **every planned cell**;
missing artifacts, failed clients, 429s, unavailable models, and mismatches all
fail. The `skip-agent-e2e` label records a deliberate whole-matrix skip. Matching
forks run credential-free contracts on GitHub-hosted runners and never start
the live matrix jobs.

## Runner and local use

All jobs run on GitHub-hosted `ubuntu-latest` runners. Each live cell uses a
fresh VM with Docker, OpenSSL and Python; the workflow sets up stable Rust
through the repository's shared action and restores cached Cargo build outputs.
The matrix and randomized Codex E2E jobs share the `agent-e2e` Rust cache key.
The workflow selects Node.js 24 and installs only the cell's client into
its temporary job directory: Codex `0.163.0`, Claude Code `2.1.206`, or DSH
`0.2.0-rc.2`. Hermes is fetched from the immutable upstream commit in
[`scripts/ci/hermes-revision.txt`](../ci/hermes-revision.txt) and installed using
Python 3.14, uv 0.12.13, and its committed `uv.lock` (`uv sync --locked --no-dev
--extra anthropic`). The Anthropic SDK is installed before testing; automatic
lazy installation is disabled. The pinned revision supports JSONL output and
`llm_request` middleware. Its Python environment lives entirely in the temporary
job directory. Installation receives no API secrets. Local runs use preinstalled
clients, Docker, Cargo/Rust, OpenSSL and Python 3.10+. Required CLI capabilities
are checked and actual versions recorded;
the job does not modify global client installations, login, CA trust or user config.
DSH uses a fresh `DSH_HOME`; Codex ignores user rules/config; Claude uses bare
mode with settings sources disabled. Hermes uses a fresh `HERMES_HOME`, disables
memory, ignores workspace rules, and configures a per-provider CA bundle containing
public roots and the test CA. It never writes to the user's Hermes installation.

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
python3 -m ruff check scripts/agent_matrix_ci scripts/tests/test_agent_matrix_ci.py scripts/tests/test_agent_hermes_matrix.py
python3 -m ruff format --check scripts/agent_matrix_ci scripts/tests/test_agent_matrix_ci.py scripts/tests/test_agent_hermes_matrix.py
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
