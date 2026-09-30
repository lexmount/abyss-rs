# Raw request and response bodies

Version 2 adds `raw_body` to Agent events. `text`, tools and token counters remain
derived projections. A request event retains the original request body; a
response event retains the original response body, including every SSE event.
`raw_body.parts[*].content_base64` decodes to the bytes seen by the transport
hook, without JSON serialization, filtering, trimming, or deduplication. The
length and SHA-256 allow consumers to verify those bytes. HTTP chunk framing
and TLS records are transport framing, not part of these entity bodies.
Content-Type and Content-Encoding are retained. WebSocket messages retain their
sequence and are not concatenated or deduplicated.

WebSocket archives are emitted when the provider sends a terminal event
(`response.completed`, `response.failed`, `response.incomplete`, or `error`).
The existing pending-turn assembler expires after one minute without messages
and retains at most 64 pending flows. A disconnected turn without a terminal
event is not durably archived by this implementation. HTTP exchanges likewise
depend on the transport delivering an exchange to its hook. These lifecycle
limits are separate from byte-preserving storage of emitted archives.

The official delivery plugin stores this object as `metadata.raw_body` in the
existing usage-event table. Retries spool the same bytes. Event detail APIs
return the archive; trajectory is a read-time projection and never rewrites it.
Every observed body receives a fresh event id; two actual provider calls are
retained even if their bodies are identical. Delivery retries preserve that id
and are idempotent at ingestion.

Raw capture requires conversation text, tool content, and image content to all
be enabled, because the original body may contain all three. Disabling a
category omits raw bodies rather than secretly retaining excluded content.
`truncated: true` explicitly means an incomplete capture; it must never be
presented as a complete body. The existing HTTP capture bound is 16 MiB per
body. V2 frames and backend ingest accept 64 MiB to accommodate base64 plus the
derived event fields. Capture completeness is therefore verifiable, not inferred
from successful protocol parsing.

The broker supports v1 and v2 concurrently and removes `raw_body` for v1
connections. The official Rust delivery client requests v2. Existing Python
and TypeScript v1 clients keep the unchanged v1 contract. Upgrade the broker
before the official delivery plugin. V1 schemas are unchanged.

Framing and control messages otherwise follow [v1](../v1/README.md).
