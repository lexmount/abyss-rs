# Codex Agent-driven E2E CI

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
use a self-hosted Codex login. The workflow deliberately does not use
`pull_request_target`.

## Runner prerequisites

The `abyss-debian-runner` is selected through its registered labels
`self-hosted`, `abyss`, `Linux`, and `X64`. Its service account must provide
these preinstalled commands:

- `bash` and `git` for the GitHub job and checkout;
- Python 3.10 or newer with the standard library;
- `cargo` and the repository's Rust toolchain/dependency cache;
- `docker` with permission to use a running broker;
- `openssl`;
- `codex`, authenticated for that same service account.

The installed Codex CLI must support `exec --json`, `--image`, `--ephemeral`,
`--ignore-user-config`, `--ignore-rules`, `--output-schema`,
`--output-last-message`, `--skip-git-repo-check`, and `--sandbox`. Run the
read-only check with:

```bash
python3 -m scripts.agent_e2e_ci preflight
```

The workflow has no package-manager or toolchain installation step. Docker pulls
the digest-pinned public Backend image recorded in
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

The internal runtime is preserved for self-hosted runner diagnostics, while
containers, the dedicated network, and broker process are stopped or removed by
the orchestrator. The shared digest-pinned Backend image remains in Docker's
local cache.

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
