# SOCKS5 upstream routing

Task: `socks5.md`. Baseline: `9c7fe41f885c9263714518ef699e18bdb8c3d4ab`.

Abyss currently negotiates every next hop with HTTP CONNECT. Add a SOCKS5
TCP CONNECT route to the same broker configuration and live-update boundary.
Existing HTTP and HTTPS configurations retain their behavior. Explicit proxy,
macOS flow ingress, and Windows redirected flows share this connector; target
TLS, HTTP inspection, event capture, and delivery remain above the tunnel.

## Configuration and negotiation

`protocol = "socks5"` requires `endpoint = "socks5://host:port"`. The existing
absolute `credentials_file` path optionally supplies JSON username/password
strings. Each SOCKS credential must contain 1–255 UTF-8 bytes. Credentials stay
inside the prepared route and never enter serialized configuration or error
messages. SOCKS5 has no proxy TLS layer, so `ca_file` remains HTTPS-only.

The shared connector owns proxy DNS, socket initialization, listener exclusion,
TCP connection, and deadlines. Separate HTTP and SOCKS handshake modules turn
that connection into a target stream. The public `HttpConnectProxy` name remains
as a compatibility alias while internal callers use `UpstreamProxy`.

Implement TCP CONNECT and the no-authentication and username/password methods
from [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) and
[RFC 1929](https://www.rfc-editor.org/rfc/rfc1929). With credentials configured,
offer only username/password, preventing silent authentication downgrade. Send
IPv4/IPv6 literals as binary addresses and DNS names as domain addresses without
local target resolution. Read exactly the reply address and port so early target
bytes stay in the stream. Validate versions, reserved bytes, address types and
authentication results; bound all negotiation phases by one handshake deadline.
Failures close the route without direct fallback. SOCKS reply codes are distinct
from HTTP statuses; authentication failures reuse the existing broker diagnostic
category without disclosing credentials. BIND, UDP ASSOCIATE, GSSAPI, SOCKS4, and
TLS to a SOCKS proxy are outside this TCP routing change.

RFC 1929 credentials travel unencrypted to the SOCKS server. Target TLS remains
independent and does not protect the proxy authentication exchange.

## Consumers and rollout

Update Rust, TypeScript, Python and OpenAPI configuration contracts together.
No event schema or backend change is needed. AbyssApp currently pins endpoint
1.4.5 and its editor only supports HTTP. This runtime change does not modify that
packaged product: enabling SOCKS in a native release requires a subsequent
endpoint release, matching library/artifact pins, editor work, and native package
validation. Do not fabricate release hashes or silently substitute local sources.

## Validation

Unit tests cover endpoint/protocol matching, credential byte bounds, each address
family, partial replies, early data, rejected methods and credentials, invalid
frames, EOF, deadlines, and unchanged HTTP behavior. A real-broker black-box suite
exercises public network configuration, HTTP and CONNECT forwarding, target TLS,
streaming, live updates/restart persistence, transparent flow ingress where
available, authentication, diagnostics and no direct fallback. Run existing
HTTP/HTTPS upstream and SDK regressions, workspace tests, formatting and clippy.

Run installed `codex` and `dsh` with provider traffic through the changed broker
and SOCKS server, using the changed delivery plugin and a real destination backend;
correlate capture with persisted query results. Final source identities, commands, results and any missing checks are recorded in
[the persistent HTML report](../../../artifacts/socks5/report.html). Required checks that cannot run
remain blockers, rather than being counted as passed.
