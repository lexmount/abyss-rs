# abyss-data-client

The synchronous Rust client for Abyss's public data HTTP contract. It owns
endpoint normalization, typed request selectors, response parsing and bounded
HTTP transport. It has no dependency on the broker, SDK, backend implementation,
profile files or credential stores.

```rust,no_run
use abyss_data_client::{ApiEndpoint, DataClient, DataClientOptions};
use abyss_data_client::query::PageQuery;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let endpoint = ApiEndpoint::parse("https://data.example.com/api/")?;
let bearer = std::env::var("ABYSS_DATA_TOKEN").ok();
let client = DataClient::new(endpoint, bearer, &DataClientOptions::default())?;
let page = client.sessions(&PageQuery::default())?;
println!("{} sessions", page.items.len());
# Ok(())
# }
```

The API root is supplied by the deployment and may include a reverse-proxy
prefix. GET operations cover `v1/agent-usage/{sessions,events,search,summary}`.
Session header, streams, turns, segments, and event conversation previews and
locations are shared reads. In-session literal search requires server support
(currently standalone SQLite). The removed `session`, `outline`, and `trajectory`
methods have no shape-compatible replacement: use `events` with `EventFields::Full`
and `session_pk` to page through all observations, structure methods for overview,
and `segment` with the default `PreviewQuery` for complete available exchange
content. The client performs no trajectory assembly or turn derivation and no
longer sends the removed `turn_index` event filter. The client returns one page;
callers own pagination policy. Event continuation tokens are decimal offsets,
while sessions/search use a one-based page and fixed page size.

`None` means anonymous authentication. HTTP 401/403 remain errors; there is no
implicit login or anonymous fallback. HTTPS verifies native trust roots and an
optional additional PEM CA bundle. Redirects are disabled. Remote plaintext
HTTP requires `ApiEndpoint::parse_with_http(..., true)`; loopback HTTP is enabled
by default. The low-level `HttpTransport` accepts caller-constructed URLs and
must be used with an endpoint validated under the caller's transport policy.

Response DTOs type stable identity and pagination fields. Flattened extension
maps retain backend metadata, full/partial content, structured search fragments
and fields introduced by newer servers. The persisted backend event DTO is
intentionally distinct from the broker's AgentEvent ingestion protocol.

`create_session_share(session_pk)` explicitly creates a snapshot through the
server's sharing API. It returns a typed share summary and a one-time capability;
callers must not log or persist that capability. Ownership, snapshot limits,
expiry, recipient access, and revocation remain server-owned. Deployments without
sharing support return an HTTP error. The CLI constructs browser links from a
separately configured frontend root; the data client does not guess that root.

Defaults are a 30-second per-attempt deadline, 8 MiB response budget, and two
transient GET retries. Authentication and share-creation POSTs are never retried. Error Display
messages do not include server bodies, tokens or response decode excerpts.
