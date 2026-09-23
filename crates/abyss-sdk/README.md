# `abyss-sdk`

Rust SDK for the local broker REST API and plugin event stream. One
`BrokerClient` owns both endpoints; `client.plugin(id)` creates an independent
`BrokerPlugin` without opening a connection.

```rust,no_run
use abyss_sdk::BrokerClient;

# async fn example() -> Result<(), Box<dyn std::error::Error>> {
let client = BrokerClient::new(
    "http://127.0.0.1:18190",
    "/path/to/runtime/broker-plugin-v1.sock",
)?;
let status = client.proxy_status().await?;
println!("{:?}", status.lifecycle);
let close = client.plugin("company.security-exporter")
    .run(|event| async move {
        println!("{}", event.event_id);
        Ok::<(), std::convert::Infallible>(())
    })
    .await?;
println!("broker close code: {}", close.code);
# Ok(())
# }
```

Alternatively, `BrokerClient::from_startup_info(path).await?` loads `api_addr`,
`plugin_endpoint`, and the bearer token from the broker startup record.
Manual clients can use `.with_bearer_token(token)` for protected REST routes.
Windows callers supply the broker's Named Pipe instead of a Unix socket path.

Each plugin owns its connection and can outlive the client. Use `connect()` to
consume an `AgentEventStream` directly, or `run(handler)` to process events until
the broker closes it. Plugins never rediscover endpoints from environment
variables. Reconnection and durable event storage belong to the consumer.

Migration: replace `AbyssPlugin::new(id).with_endpoint(endpoint)` with
`BrokerClient::new(api_url, endpoint)?.plugin(id)`. `AbyssPluginError` is now
`BrokerPluginError`; the wire protocol is unchanged.
