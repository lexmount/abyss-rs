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
