# `abyss-sdk`

Rust SDK for the local `abyss-broker` REST API and plugin event stream.

Add the published SDK to your project:

```bash
cargo add abyss-sdk
```

The broker runs as a separate process. The SDK provides local REST management
and plugin event consumption; it does not handle remote event upload or
control-plane authentication.

```rust,no_run
use abyss_sdk::BrokerClient;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = BrokerClient::new("http://127.0.0.1:18190")?;
let status = client.proxy_status().await?;
println!("{:?}", status.lifecycle);
# Ok(())
# }
```

```rust,no_run
use abyss_sdk::plugin::BrokerPlugin;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let close = BrokerPlugin::new("company.security-exporter")
    .run(|event| async move {
        println!("{}", event.event_id);
        Ok::<(), std::convert::Infallible>(())
    })
    .await?;
println!("broker close code: {}", close.code);
# Ok(())
# }
```

## Request inspection

A connected request handler enables `agent_request` inspection on the existing
plugin connection. See the [request inspection example](examples/request_inspection.rs). No broker
inspector configuration is needed. Event observation is an independent capability.
Use the complete decoded body/JSON and parsing status as well as the normalized
Agent projection when implementing a policy; unknown protocols still reach the
handler. Credential headers are omitted and explicit proxy process fields are absent.
Return a safe block reason that does not contain the rejected content.

Plugins run in registration order, and each sees earlier accepted modifications.
Return Allow, Block with a safe reason, or Modify with explicit Set/Remove actions
for the selected auth token or model. `auth_token_writable` and `model_writable`
indicate supported edits. See the [model override example](examples/request_modification.rs). The SDK sends only the decision; it never diffs context.
Request handlers can read `auth_token`; event subscribers cannot.
See the [v1 wire contract](https://github.com/lexmount/abyss-rs/tree/main/specs/broker-plugin-protocol/v1).
Broker and SDKs share the updated v1 contract. A selected
plugin that fails or does not respond within five seconds fails that request.
Disconnecting the last inspection plugin restores normal streaming for future
requests. Network policy Block and opaque TLS Passthrough never invoke this callback.
