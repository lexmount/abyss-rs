# abyss-mitm

Shared TLS interception and HTTP stream handling for the
[Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).

This library provides explicit and adapter-fed traffic handling, HTTP and
WebSocket relay hooks, TLS decryption policy, and root CA lifecycle APIs.
`MitmEngine` owns shared traffic processing; `CaStore` owns CA material loading
and generation. Platform redirection and product lifecycle remain with callers.

HTTP forwarding preserves `Accept-Encoding`, original content headers, and body
bytes for every host and route. After transfer framing is removed, the background
hook worker decodes `Content-Encoding` for both requests and responses: gzip,
zlib-wrapped deflate, Brotli, zstd, and identity. Stacked codings are decoded in
reverse order, including repeated header fields.
When both captures already have usable uncompressed views, the hook worker
reuses their bytes and parsed JSON without scheduling a blocking decode task.
This includes valid `identity` codings and dechunked bodies. Either compressed
side, invalid encoding metadata, or a required output-limit adjustment uses
the blocking decoder.

`CapturedBody::bytes()` and `json()` expose the observation view; `raw_bytes()`
and `raw_truncated()` retain the encoded capture. Headers always describe the
raw representation. `decoding_status()` distinguishes complete, truncated,
pending, unsupported, corrupt, and budget-limited captures. Immediate relay
outcomes have pending encoded bodies; hooks receive the processed view.

Encoded capture and decoded output have independent limits based on the engine's
body capture setting; decoded output and intermediate layers are additionally
capped at 16 MiB. Decoding accepts at most four codings, bounds codec windows to
16 MiB, and checks a two-second processing budget per body between bounded codec
steps. A capture/output limit retains a decoded prefix. Invalid or unsupported
encodings expose an empty observation view with explicit status. Failures and
hook queue pressure never change forwarded traffic. Transfer compression other
than chunk framing is reported as unsupported. WebSocket extension negotiation
remains separate; the relay still removes `Sec-WebSocket-Extensions` because it
does not implement `permessage-deflate`.

Interception requires clients to trust the configured CA. Certificate pinning,
mTLS, QUIC/HTTP/3, and application-specific trust stores can limit inspection.
MITM observation does not isolate an agent's filesystem or process access.

The TLS implementation uses AWS-LC and requires a native C/C++ build toolchain.
To install the standalone proxy, use `cargo install --locked abyss-broker`.
This crate is a library and does not install a command.

Licensed under GPL-3.0; see the included `LICENSE` file.
