# abyss-mitm

Shared TLS interception and HTTP stream handling for the
[Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).

This library provides explicit and adapter-fed traffic handling, HTTP and
WebSocket relay hooks, TLS decryption policy, and root CA lifecycle APIs.
`MitmEngine` owns shared traffic processing; `CaStore` owns CA material loading
and generation. Platform redirection and product lifecycle remain with callers.

HTTP forwarding removes `Accept-Encoding` from POST requests whose paths end in
`/responses`, `/chat/completions`, or `/messages`, on any host. It also retains
the existing exception for `anthropic.com`, `claude.ai`, `dmxapi.cn`, and their
subdomains. This aims to obtain uncompressed responses for Agent parsing.
Other requests preserve their compression negotiation. Request and response
body bytes remain unchanged; captures remove HTTP transfer framing but do not
decode content encodings such as gzip and Brotli.

Interception requires clients to trust the configured CA. Certificate pinning,
mTLS, QUIC/HTTP/3, and application-specific trust stores can limit inspection.
MITM observation does not isolate an agent's filesystem or process access.

The TLS implementation uses AWS-LC and requires a native C/C++ build toolchain.
To install the standalone proxy, use `cargo install --locked abyss-broker`.
This crate is a library and does not install a command.

Licensed under GPL-3.0; see the included `LICENSE` file.
