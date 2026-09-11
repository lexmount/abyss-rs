# abyss-agent-hook

AI agent protocol parsing for the [Abyss endpoint runtime](https://github.com/lexmount/abyss-rs).

This library consumes decoded HTTP and WebSocket traffic from `abyss-mitm`,
identifies supported agent harnesses and provider protocols, correlates requests
and responses, and produces typed `abyss-plugin-protocol` events. Runtime policy
controls which normalized content categories are included.

`HarnessUsageHook` connects the parsing pipeline to MITM traffic, and
`AgentEventSink` lets the caller supply an event consumer. Remote delivery and
authentication belong to consumers outside this crate.

To install the standalone proxy, use `cargo install --locked abyss-broker`.
This crate is a library and does not install a command.

Licensed under GPL-3.0; see the included `LICENSE` file.
