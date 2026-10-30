# abyss-query

`abyss-query` is a Rust CLI for Agents and people to read data from an Abyss SaaS
or self-hosted HTTP backend. It runs on Windows, Linux and macOS without a
broker, proxy, CA installation or local database. The Cargo package is
`abyss-query-cli`; the installed executable is `abyss-query`.

```sh
cargo install --locked abyss-query-cli
# From a checkout:
cargo build --locked -p abyss-query-cli
```

## Profiles and authentication

API roots are deployment-supplied. Include the reverse proxy prefix (for
example `/api/`) when the deployment requires it. No production endpoint is
compiled into the binary. The first profile becomes active automatically.

```sh
abyss-query profile add local --endpoint http://127.0.0.1:8080/ \
  --auth bearer --header-file /absolute/path/to/backend-header
abyss-query doctor
abyss-query sessions list

abyss-query profile add cloud --endpoint https://data.example.com/api/ \
  --auth terminal --auth-endpoint https://auth.example.com/
abyss-query --profile cloud auth login
abyss-query --profile cloud search "authentication error"
```

`--header-file` accepts exactly one `Authorization: Bearer TOKEN` header, such
as the file produced by the official local deployment. `--token-file` accepts
one raw token; `--token-env VARIABLE_NAME` reads a raw token from that environment
variable. No token argument is offered, and profile files contain references
rather than secrets. Relative file references are resolved when adding a profile.

The official local backend requires authentication. An anonymous profile is
only appropriate for a backend that explicitly permits anonymous reads:

```sh
abyss-query profile add public --endpoint https://data.example.com/ --auth none
```

Anonymous mode never resolves credentials. A 401 never triggers a fallback or
browser login. Terminal login is explicit: it prints a browser verification URL
to **stderr**, waits for authorization, and stores the exchanged credential.
The existing terminal-auth PKCE contract is reused; there is no refresh-token
contract, so expired credentials require another `auth login`.

The default terminal credential store is macOS Keychain, Windows Credential
Manager or Linux Secret Service. Headless Unix systems without a secret-service
session can choose `--credential-store file` when adding the profile; this uses
atomic replacement and mode 0600. Windows uses its OS keyring. Bearer environment
and file sources work on every platform. Stored terminal credentials are bound
to the profile name and normalized data/auth roots.

```sh
abyss-query profile list
abyss-query profile show cloud
abyss-query profile use cloud
abyss-query auth status
abyss-query auth logout
```

`auth status` reports local availability/expiry, not live authorization. `doctor`
performs an actual one-session read. `auth logout` revokes the session before
removing it locally; a failed revocation retains the credential. Explicit
`auth logout --local-only` and `profile remove NAME` only delete local state.
Use logout before removing a terminal profile when remote revocation is needed.
Profiles cannot be silently overwritten; remove and re-add them to change roots.

The default config uses the platform application configuration directory.
`--config PATH` / `ABYSS_QUERY_CONFIG` and `--profile NAME` /
`ABYSS_QUERY_PROFILE` override the selection. Configuration updates are locked
and atomically replaced. Configuration files use version 1.

Remote HTTP requires explicit `profile add --allow-http`, which also permits
sending credentials without TLS. Loopback HTTP works by default. HTTPS verifies
hostnames and the platform trust roots; `--ca-file PEM` adds a private CA without
disabling validation. Redirects are never followed, including during login.

## Query commands

Commands shared by the SaaS data service and the standalone backend:

```sh
abyss-query sessions list --agent codex --from 2026-10-01T00:00:00Z
abyss-query events list --session-pk SESSION_UUID --full
abyss-query events get EVENT_UUID
abyss-query search "retry timeout" --provider openai
abyss-query usage summary --group-by agent_name,llm_model
abyss-query schema
```

SaaS data service only:

```sh
abyss-query sessions get SESSION_UUID
abyss-query sessions outline SESSION_UUID
abyss-query sessions trajectory SESSION_UUID
abyss-query events list --turn-index 3
abyss-query usage summary --global
```

Standalone backend only:

```sh
abyss-query sessions header SESSION_UUID
abyss-query sessions streams SESSION_UUID
abyss-query sessions turns SESSION_UUID
abyss-query sessions segment SESSION_UUID SEGMENT_HEAD --entries=-2 --text-preview 200
abyss-query sessions search SESSION_UUID "retry timeout"
abyss-query events list --session-pk SESSION_UUID --locate
abyss-query events conversation EVENT_UUID --entries 0-3,-1 --text-preview 200
abyss-query events location EVENT_UUID
```

`--agent`, `--provider` and `--model` repeat for OR matches within a dimension.
`--from` is inclusive; `--to` is exclusive. Session/detail IDs are backend UUIDs;
`events list --session-id` filters the Agent's native session ID instead.
Event lists omit full content unless `--full` is supplied. Outline, trajectory,
session page structure, conversation previews, unknown fields, structured search
highlights and partial-content indicators are preserved as returned by the
backend. Missing content or usage is not invented. `--entries` takes
comma-separated runs (`a-b`, `-n` for the last n, `a`), validated by the
backend; write `--entries=-n` when the value starts with `-`. `--text-preview`
caps each entry text in UTF-16 code units.

`usage summary --global` requests the SaaS global scope; the server decides
whether the current principal is authorized. Ordinary queries do not request
global scope. Search availability and accepted summary dimensions are determined
by the backend. Disabled search is reported as an HTTP error, not an empty result.

A list/search fetches one page by default. Explicit `--all` follows continuation
metadata, with defaults of 1,000 items and 100 pages; hard maxima are 100,000
items and 1,000 pages. Sessions/search use a fixed `--page-size` and one-based
`--page`; events use `--limit` and decimal `--offset` continuation tokens.
Session pagination stops before a page that could exceed the item budget, so
it may return fewer items than `--max-items`. `meta.next` resumes the exact
window, and `meta.truncated` reports a reached `--all` bound. Backend datasets
can change between requests; pagination does not provide snapshot isolation.

Each HTTP response is limited to 8 MiB by default, configurable up to 64 MiB.
Combined paginated output is also limited to 64 MiB; exceeding this fails before
printing results. `profile add --timeout SECONDS` sets the per-attempt deadline
(default 30, maximum 600), and `--retries` allows up to three GET retries (default
two). Only connection/timeouts and 429/502/503/504 responses are retried.
`Retry-After` up to five seconds is honored; longer/invalid delays return the
HTTP error immediately. Auth POSTs are never replayed. Query execution time is
bounded by the selected page budget, request deadlines and retry delays.

## Agent output contract

JSON is the default. Stdout contains one versioned envelope:

```json
{"schema_version":1,"command":"sessions.list","data":[],"meta":{"pages":1,"next":null,"truncated":false,"backend":{"total_sessions":0,"page":1,"page_size":20,"has_more":false}}}
```

Paginated commands return records in `data`; `meta.backend` retains metadata from
the last page. Detail and summary commands return the backend object in `data`.
`--format jsonl` emits one `{schema_version,command,record}` object per item and
a final `{schema_version,command,meta}` line. Results are collected before output,
so JSONL does not stream partially successful queries. `--format table` emits
escaped tabular identifiers plus full JSON rows. `schema` returns JSON Schemas
for the envelope and the typed backend DTOs without connecting to a server.

Errors are a single JSON object on stderr with `schema_version` and
`error.{code,message,http_status}`. HTTP error bodies, decode excerpts, tokens
and echoed invalid arguments are excluded. Successful explicit login also emits
its verification instruction on stderr. Exit codes:

| Code | Meaning |
| --- | --- |
| 0 | Success (including a consumer closing a pipe) |
| 2 | Arguments, configuration or query validation |
| 3 | Missing/expired credentials or HTTP 401 |
| 4 | HTTP 403 |
| 5 | HTTP 404 |
| 6 | HTTP 429 after bounded retries |
| 7 | Transport failure or timeout |
| 8 | Other non-success HTTP status, including redirects |
| 9 | Invalid response, pagination or size limit |
| 10 | Local I/O or serialization failure |

## Validation

```sh
cargo test --locked -p abyss-data-client -p abyss-query-cli
cargo clippy --locked -p abyss-data-client -p abyss-query-cli --all-targets -- -D warnings
python3 scripts/tests/query_backend_e2e.py \
  --query target/debug/abyss-query --backend /path/to/sqlite-fts/abyss-backend
```

Tests run actual CLI processes against TCP servers and a real TLS server. The
optional backend scenario starts an isolated SQLite+FTS backend, ingests events,
then checks all query views, real FTS, pagination and required authentication.
It needs a separately supplied backend executable and no production credentials.
