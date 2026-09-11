# abyss-mitm

Shared TLS interception and HTTP stream handling for the
[Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).

This library provides explicit and adapter-fed traffic handling, HTTP and
WebSocket relay hooks, TLS decryption policy, and root CA lifecycle APIs.
`MitmEngine` owns shared traffic processing; `CaStore` owns CA material loading
and generation. Platform redirection and product lifecycle remain with callers.

Interception requires clients to trust the configured CA. Certificate pinning,
mTLS, QUIC/HTTP/3, and application-specific trust stores can limit inspection.
MITM observation does not isolate an agent's filesystem or process access.

The TLS implementation uses AWS-LC and requires a native C/C++ build toolchain.
To install the standalone proxy, use `cargo install --locked abyss-broker`.
This crate is a library and does not install a command.

Licensed under GPL-3.0; see the included `LICENSE` file.
