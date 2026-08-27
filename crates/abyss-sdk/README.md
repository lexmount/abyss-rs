# `abyss-sdk`

Rust SDK for the local `abyss-broker` REST API and plugin event stream.

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
use abyss_sdk::plugin::AbyssPlugin;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let close = AbyssPlugin::new("company.security-exporter")
    .run(|event| async move {
        println!("{}", event.event_id);
        Ok::<(), std::convert::Infallible>(())
    })
    .await?;
println!("broker close code: {}", close.code);
# Ok(())
# }
```
