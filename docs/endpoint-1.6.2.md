# Endpoint 1.6.2 release

WorkBuddy 5.11.3 starts its macOS daemon with the inline Node option
`--disable-warning=ExperimentalWarning` before the daemon script. In 1.6.1 the
broker lost the script identity at this option and attempted TLS interception
on a connection covered by the daemon passthrough rule. WorkBuddy rejected the
certificate. Version 1.6.2 recognizes the inline option when identifying a
direct Node or Electron script. The existing passthrough rule then matches the
daemon and WorkBuddy can validate its upstream certificate.

The release also includes Linux TUN ingress for transparent TCP and fixes for
reusing the Linux CA trust and broker owned by the current installation. See the
[changes since 1.6.1](https://github.com/lexmount/abyss-rs/compare/v1.6.1...v1.6.2).

The five endpoint archives and the Rust workspace crates use version 1.6.2.
Consumers can verify the archive checksums and embedded source revision against
the release and pin the matching registry version of `abyss-mitm`.
