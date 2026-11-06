//! Minimal request-only policy plugin. The marker check illustrates the callback API.

use abyss_sdk::plugin::{BrokerPlugin, RequestDecision};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    BrokerPlugin::new("example.request-policy")
        .on_agent_request(|context| async move {
            let contains_marker = context.agent.as_ref().is_some_and(|agent| {
                agent
                    .conversation
                    .entries
                    .iter()
                    .any(|message| message.text.contains("PRIVATE KEY"))
            });
            let decision = if contains_marker {
                RequestDecision::Block("Private key detected".to_owned())
            } else {
                RequestDecision::Allow
            };
            Ok::<_, std::convert::Infallible>(decision)
        })
        .run()
        .await?;
    Ok(())
}
