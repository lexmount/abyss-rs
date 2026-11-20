//! Run the management server and broker inspector for the same worker lifetime.

use abyss_sdk::plugin::{BrokerPlugin, RequestDecision};
use serde::Deserialize;
use std::{
    convert::Infallible,
    fs::OpenOptions,
    future::ready,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::{rest, store::Store, sys};

#[derive(Deserialize)]
struct Startup {
    pid: u32,
    plugin_endpoint: String,
}

#[cfg(unix)]
pub fn system_endpoint(startup: &Path) -> PathBuf {
    startup.with_file_name("model-route.sock")
}

#[cfg(windows)]
pub fn system_endpoint(_startup: &Path) -> PathBuf {
    PathBuf::from(r"\\.\pipe\abyss-model-route-v1")
}

#[expect(
    clippy::integer_division_remainder_used,
    reason = "Tokio selects the first completing service using internal scheduler arithmetic."
)]
pub async fn run(
    startup: PathBuf,
    endpoint: PathBuf,
    profile: Option<PathBuf>,
) -> Result<(), &'static str> {
    let broker: Startup =
        serde_json::from_slice(&std::fs::read(&startup).map_err(|_| "Broker unavailable.")?)
            .map_err(|_| "Invalid broker startup information.")?;
    let directory = profile.as_ref().map_or_else(
        || startup.with_file_name("model-route-state"),
        |p| p.with_extension("routes"),
    );
    sys::private_directory(&directory).map_err(|_| "Cannot secure route state directory.")?;
    let lifetime = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(directory.join("worker.lock"))
        .map_err(|_| "Cannot create worker lifetime lock.")?;
    lifetime
        .try_lock()
        .map_err(|_| "Model routing worker already running.")?;
    let store = Arc::new(Store::open(directory, broker.pid)?);
    let personal = profile.is_some();
    let inspection = Arc::clone(&store);
    let (signal, connected) = tokio::sync::oneshot::channel();
    let plugin = BrokerPlugin::new("abyss.model-route")
        .with_endpoint(broker.plugin_endpoint)
        .on_agent_request(move |context| {
            let decision = context
                .harness
                .as_ref()
                .and_then(|_| context.source_process.as_ref()?.pid)
                .and_then(sys::process_principal)
                .and_then(|principal| inspection.get(&principal))
                .map_or(RequestDecision::Allow, |r| r.inspect(&context));
            ready(Ok::<_, Infallible>(decision))
        })
        .run_with_ready(move || {
            let _sent = signal.send(());
        });
    let management = async move {
        connected
            .await
            .map_err(|_| "Broker plugin handshake failed.")?;
        let listener = sys::Listener::bind(&endpoint, personal)
            .await
            .map_err(|_| "Cannot open routing control endpoint.")?;
        rest::serve(listener, store).await
    };
    tokio::select! {
        biased;
        result = plugin => result.map(|_| ()).map_err(|_| "Broker plugin session failed."),
        result = management => result,
    }
}
