//! Explicit semantic model override; credential allocation can return auth actions similarly.

use abyss_sdk::plugin::{BrokerPlugin, ModifyAction, RequestDecision};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let model = std::env::var("ABYSS_MODEL_OVERRIDE")?;
    BrokerPlugin::new("example.model-override")
        .on_agent_request(move |context| {
            let decision = if context.model_writable {
                RequestDecision::Modify(Box::new([ModifyAction::SetModel(model.clone())]))
            } else {
                RequestDecision::Allow
            };
            async move { Ok::<_, std::convert::Infallible>(decision) }
        })
        .run()
        .await?;
    Ok(())
}
