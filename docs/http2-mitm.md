# HTTP/2 MITM

Task: `http2.md`. Baseline: `9c7fe41f885c9263714518ef699e18bdb8c3d4ab`.

The existing MITM terminates TLS without ALPN and decodes only HTTP/1. Clients
that require HTTP/2 cannot use the intercepted connection. HTTP/1 clients,
WebSocket upgrades, passthrough, routing, and request inspection must retain
their existing behavior.

## Protocol selection and ownership

When an intercepted ClientHello offers `h2`, connect the policy-selected origin
first and offer only supported protocols also offered by that client. Mirror
the origin's ALPN selection into the client handshake. This preserves a common
protocol on both TLS legs, including HTTP/1 fallback for origins without HTTP/2,
without translating application messages between HTTP versions. Clients that
do not offer `h2` retain the existing HTTP/1 path. TLS identity, destination port,
configured CONNECT routing, certificate validation, and redirects retain their
existing owners. Proxy-hop CONNECT continues to use HTTP/1.1.

The new HTTP/2 relay uses the maintained `h2` crate for HPACK, framing, settings,
stream lifecycle, and protocol validation. One connection driver serves at most 32 concurrent stream futures, with 64 KiB
header lists and 16 KiB send queues. Each stream validates authority, applies the selected
redirect, runs the existing request-control contract, forwards DATA and trailers
with flow control, and submits its own `HttpExchange`. A reset affects its stream,
not unrelated requests. Observation retains bounded body prefixes; forwarding
does not truncate at the capture limit. Inspection retains and decodes a complete
bounded request before sending request headers or bytes to the origin.

Captured and inspected heads include a synthesized `Host` for existing Agent
parsers. The upstream HTTP/2 head uses only `:authority`; forwarding both fields
causes strict gateways such as Qwen's to reject valid requests with an empty 400.
This normalization applies after inspection and redirects, while preserving the
observer-facing authority and original destination validation.

Response cancellation preserves bytes already observed and marks the capture as
truncated unless the origin's end-of-stream was consumed. This includes clients
that stop after an application-level terminal event, before HTTP/2 END_STREAM.
The origin stream is canceled immediately; no background draining is introduced.
Connection teardown polls ready captures once before dropping unfinished work.

HTTP versions on captured request/response heads distinguish HTTP/2 without
changing the normalized event schema or the public TLS transport enum. Existing
body decoding and hook dispatch remain shared. HTTP/2 CONNECT, extended CONNECT
(including WebSocket over HTTP/2), cleartext h2c (prior knowledge or upgrade), and HTTP/3 are outside this change;
ordinary HTTPS HTTP/2 is the target. Native packages consume pinned releases and
will not gain this behavior until their endpoint dependency is upgraded.

## Validation

Unit coverage exercises bounded capture. Fifteen HTTP/2 tests include real
TCP/TLS exchanges for multiplexed requests, large streaming bodies, trailers,
cancellation before and after response headers, retained partial captures on
stream reset and connection disconnect, redirect/control behavior,
authority rejection, single-authority forwarding with observer Host retention,
HTTP/1 fallback, and `100 Continue`/`103 Early Hints`.
`make test-blackbox-http2` runs the engine socket cases. The standalone Node
probe in `scripts/blackbox_http2.mjs` sends three concurrent 96 KiB JSON requests
through a running broker to a publicly trusted HTTP/2 echo service; set
`ABYSS_HTTP2_PROXY_URL` and `ABYSS_HTTP2_CA_FILE` to its isolated test listener and
CA. The origin and echo path can be overridden with `ABYSS_HTTP2_ORIGIN` and
`ABYSS_HTTP2_PATH`. Public service availability is reported separately from local
deterministic tests. Required checks also
include workspace tests, formatting, Clippy, SDK regression tests, and installed
Codex/dsh traffic through the built broker and delivery plugin into a real
standalone backend. Final revisions, commands, outcomes, and review evidence are delivered in the
task's persistent HTML report. This is an endpoint-only change: no event schema,
backend migration, or packaged release pin changes are needed in this PR.

Protocol references: [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113.html),
[`h2` flow control](https://docs.rs/h2/latest/h2/struct.SendStream.html).

CI also exercises real Codex inspection and delivery. Its failure artifact now
includes bounded HTTP/2 lifecycle and content-decoder metadata, without request
headers or bodies. The HTTP data-client fixture explicitly closes each HTTP/1
connection, preventing retry/pool reuse races. The DSH Anthropic matrix case
uses non-thinking mode because its native Messages adapter cannot emit the
required Anthropic thinking budget; tool, capture, and exact usage assertions
remain enabled.
