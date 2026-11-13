# Session sharing from abyss-query

`abyss-query sessions share SESSION_PK` creates a read-only session snapshot using
the existing authenticated `POST v1/agent-usage/sessions/{session_pk}/shares`
contract. It returns a browser URL and the server's share summary in the usual
versioned output envelope. The argument is a backend session UUID, consistent
with the other session detail commands.

The data client owns the typed response and authenticated HTTP call. The CLI
owns the browser URL: `API_ORIGIN/shared/sessions/SHARE_ID#token=ENCODED_TOKEN`.
The fragment matches the product frontend and is never sent as a URL query
parameter. The product API and browser application share an origin: retain the
configured endpoint's scheme, host and port, and replace its API path with the
site-root share route. For example, an endpoint of `https://example.com/api/`
produces `https://example.com/shared/sessions/SHARE_ID#token=...`. The deployment
contract does not require a separate frontend address, so profiles and commands
have no additional URL configuration. API request routing retains its existing
prefix. Existing published profiles work without changes.

Creation is an explicit mutation. It never runs during reads or doctor checks,
does not retry POSTs, does not open a browser, and does not persist the returned
capability. The URL is disclosed only in the requested command output. HTTP
failures keep the existing sanitized diagnostics and exit codes. A timeout can
mean the server created the snapshot; callers should inspect the web share list
before retrying. The server remains responsible for ownership, snapshot
membership, expiry, limits, recipient authentication, and revocation. Standalone
backends without sharing return their normal unsupported-route error.

No service, storage, or web contract changes are required. The companion AbyssApp
PR updates the English and Chinese distributed query skills. No native app or
installer inputs change. A future query CLI release must precede distributing
skills to users of old CLIs; skill instructions check `sessions share --help`
and do not assume that existing 1.5.0 binaries implement the new command.

Validation covers same-origin URLs, API path removal, ports, IPv6, capability
encoding and invalid responses, real CLI HTTP
requests, authentication, failure codes, non-retry semantics, JSON/JSONL/table
output, schemas, and compatibility with old profiles. A live local product API
scenario must establish that the generated URL reads the intended snapshot,
enforces recipient authentication, and becomes unavailable after revocation.
Both installed codex and dsh harnesses must load and execute the changed skill
against the candidate CLI and synthetic session. Final evidence, revisions and
companion links are recorded in the task's persistent HTML report.

Implementation: [abyss-rs PR #84](https://github.com/lexmount/abyss-rs/pull/84).
Companion: [AbyssApp PR #85](https://github.com/lexmount/AbyssApp/pull/85) and
[its skill design](https://github.com/lexmount/AbyssApp/blob/task/abyss-query-session-sharing/docs/abyss-query-session-sharing.md).
Local validation passed 799 workspace tests (three existing ignored), all 17 CLI
process tests, and workspace clippy. Real Identity/Agent Data services verified
creation, owner scoping, recipient authentication, frozen snapshots and
revocation. Installed codex 0.167.0 and dsh 0.2.0-rc.2 each loaded the exact
candidate skill bundle and created one usable share, verified by a separate
recipient read. The persistent report is
`artifacts/abyss-query-session-sharing/test-report.html` under the coordinator
workspace; it includes final revisions, commands, CI and review artifacts.
