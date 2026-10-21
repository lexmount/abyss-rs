# Codex Agent-driven E2E CI

The complementary [headless harness × model matrix](../agent_matrix_ci/README.md)
covers Codex, Claude Code and DSH across provider protocols. Both GitHub
workflows use repository API Secrets; this workflow uses
`CODEX_API_KEY` for all three Codex phases. No runner login is needed
when that key is supplied; local runs can still use an existing login when the
environment variable is absent.

This package powers `.github/workflows/codex-agent-e2e.yml`. It runs a fresh
black-box topology for every pull request:

```text
Codex A1 -> randomized scenario plan
                         |
                         v
Codex B -> explicit abyss-broker proxy -> OpenAI
                         |
                         v
          abyss-delivery-plugin
                         |
                         v
              abyss-backend -> PostgreSQL
                         |
                         v
Codex A2 <- credential-free evidence bundle
```

Only Codex B receives `HTTP_PROXY`, `HTTPS_PROXY`, `CODEX_CA_CERTIFICATE`, and
`SSL_CERT_FILE`. Both Codex A phases connect directly, so their traffic cannot
be mistaken for the system under test. A1 generates the task, UTF-8 fixture
files, and a bounded PNG specification from a recorded seed. Trusted Python
code validates and materializes that plan. A2 runs in a fresh Codex session and
compares B's real JSONL trace with Backend events, attachment downloads, spool
state, and broker diagnostics.

Usage comparisons use the shared `UsageAccounting` calculation also exercised
by the fixed Codex black-box test. All captured events and provider counters
remain in the evidence. Only explicit `metadata.purpose: prewarm` events
(WebSocket `response.create` with `generate: false`) are reported separately
from completed inference usage. Event position, prompt text and token gaps are
never classification signals. The evidence includes all-observed, prewarm,
inference and native Codex totals, plus exact per-counter differences. Abyss's
disjoint input/cache counters are converted to Codex's inclusive-input convention;
reasoning is a subset of output. Missing or unmarked calls are never subtracted
to make the totals agree.

The orchestrator validates contracts and infrastructure but does not replace
A2 with fixed semantic assertions. Its final states are:

- `pass`: target tool/image coverage occurred and A2 found the capture faithful;
- `fail`: A2 found a demonstrated mismatch or infrastructure failure;
- `inconclusive`: B or the evidence did not exercise enough target behavior;
- `skipped`: the workflow recorded an authorized skip before checking out or
  executing PR code.

Both `fail` and `inconclusive` return a failing process status. A maintainer can
add the `skip-agent-e2e` PR label when a human-reviewed exception is appropriate.
The successful skipped check records the actor, commit, and reason in the GitHub
Job Summary. Fork pull requests are skipped automatically because they must not
use provider API credentials. The workflow deliberately does not use
`pull_request_target`.

## Runner prerequisites

CI runs on GitHub-hosted `ubuntu-latest`. The workflow sets up stable Rust with
the repository's shared action and Cargo build cache, selects Node.js 24, and
installs Codex `0.163.0` into the job's temporary directory. It shares the
`agent-e2e` Rust cache key with the headless matrix. No persistent runner login
or preinstalled Codex CLI is required.

The shared `setup-codex-sandbox` action installs distribution bubblewrap and
loads its AppArmor user-namespace profile. It probes Codex's read-only and
workspace-write sandbox modes before invoking models. This follows the
[official sandbox prerequisites](https://learn.chatgpt.com/docs/sandboxing#prerequisites)
and keeps sandbox enforcement enabled on Ubuntu 24.04. Local Linux runners
must also provide a functioning bubblewrap sandbox.

For local runs, provide these commands:

- `bash` and `git` for the GitHub job and checkout;
- Python 3.10 or newer with the standard library;
- `cargo` and the repository's Rust toolchain/dependency cache;
- `docker` with permission to use a running broker;
- `openssl`;
- `codex`, with `CODEX_API_KEY` supplied by GitHub (or an existing
  service-account login for local runs without that variable).

The installed Codex CLI must support `exec --json`, `--image`, `--ephemeral`,
`--ignore-user-config`, `--ignore-rules`, `--output-schema`,
`--output-last-message`, `--skip-git-repo-check`, and `--sandbox`. Run the
read-only check with:

```bash
python3 -m scripts.agent_e2e_ci preflight
```

Docker pulls the digest-pinned public Backend image recorded in
`scripts/ci/abyss-backend-image.txt` and may also need `postgres:16`. Pre-cache
those images on the runner if CI must operate without downloading inputs. Real
test traffic requires outbound access to the Codex/OpenAI endpoints.

## Runtime isolation and artifacts

Every run creates unique Docker container names, a unique Docker network,
loopback-only ports, a fresh PostgreSQL database, a short-lived CA, and a fresh
deployment bearer. It never installs the CA in the system trust store. The raw
bearer, broker control token, and CA private key remain under the mode
`0700` runtime root and are never copied into artifacts.

The uploaded `artifacts` directory contains only:

- the generated scenario plan and seed;
- Codex B observations and Backend comparison evidence;
- downloaded attachment hashes and sizes, never bearer credentials;
- the structured A2 verdict and runner version inventory;
- a Markdown summary.

The orchestrator stops or removes containers, the dedicated network, and broker
process. On GitHub-hosted runners, the internal runtime and Docker cache are
discarded with the VM after the job; only sanitized artifacts are uploaded.
Local runs retain the internal runtime for diagnostics and Docker's image cache.

## Configuration

The workflow sets the run identity and runtime root. Optional environment
variables include:

- `ABYSS_AGENT_E2E_SEED` for reproducible scenario generation;
- `ABYSS_AGENT_E2E_MAX_SCENARIOS` from 1 through 3;
- `ABYSS_AGENT_E2E_GENERATOR_MODEL`, `ABYSS_AGENT_E2E_B_MODEL`, and
  `ABYSS_AGENT_E2E_JUDGE_MODEL` to override the Codex default model;
- `ABYSS_AGENT_E2E_CODEX_TIMEOUT_SECONDS`;
- `ABYSS_AGENT_E2E_STARTUP_TIMEOUT_SECONDS`;
- `ABYSS_AGENT_E2E_EVENT_TIMEOUT_SECONDS`;
- `ABYSS_AGENT_E2E_BACKEND_IMAGE` to test an explicitly selected compatible
  Backend image instead of the repository pin;
- `ABYSS_AGENT_E2E_BACKEND_PLATFORM` when the selected image is not
  `linux/amd64`.

Run contract tests without Docker or provider traffic:

```bash
python3 -m unittest discover -s scripts/tests -p 'test_agent_e2e_*.py'
```

Run the full real-provider flow only from a prepared Linux runner:

```bash
python3 -m scripts.agent_e2e_ci run
```
