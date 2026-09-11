# abyss-plugin-protocol

Broker/plugin wire types for the [Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).

This library defines versioned handshake and control messages plus the typed
`AgentEvent` schema shared by brokers and event consumers. Transport runtimes,
remote destinations, and authentication are implemented by callers.

See the [v1 protocol specification](https://github.com/lexmount/abyss-rs/tree/main/specs/broker-plugin-protocol/v1)
for framing, lifecycle, and event examples.

To install the standalone proxy, use `cargo install --locked abyss-broker`.
This crate is a library and does not install a command.

Licensed under GPL-3.0; see the included `LICENSE` file.
