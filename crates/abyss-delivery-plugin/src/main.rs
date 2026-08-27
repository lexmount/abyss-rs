//! Official configurable HTTP delivery plugin for broker Agent events.

#![expect(
    clippy::multiple_crate_versions,
    reason = "the SDK transport and reqwest TLS dependency graphs require distinct transitive versions"
)]

use std::{path::PathBuf, sync::Arc};

use abyss_delivery_plugin::{
    DeliveryAuthenticationManager, DeliveryControlServer, DeliveryPluginConfig,
    DeliveryPluginError, EventUploader, WorkerStartupInfoGuard,
};
use abyss_sdk::plugin::{AbyssPlugin, AbyssPluginError};
use clap::Parser;
use futures_util::StreamExt as _;

/// Runs the official Agent event delivery plugin.
#[derive(Parser)]
struct Arguments {
    /// Product-owned JSON configuration file.
    #[arg(long)]
    config: Option<PathBuf>,
    /// Product lifecycle readiness file written after the broker handshake.
    #[arg(long)]
    startup_info_file: Option<PathBuf>,
    /// Broker process identity associated with the readiness file.
    #[arg(long, requires = "startup_info_file")]
    broker_pid: Option<u32>,
    /// Per-process bearer token protecting the product-local control API.
    #[arg(long)]
    control_token_file: Option<PathBuf>,
    /// Allow the containing product's runtime group to read discovery files.
    #[arg(long)]
    group_readable_control_files: bool,
}

#[tokio::main]
async fn main() -> Result<(), DeliveryPluginError> {
    let arguments = Arguments::parse();
    run(arguments).await
}

async fn run(arguments: Arguments) -> Result<(), DeliveryPluginError> {
    let config = DeliveryPluginConfig::load(arguments.config.as_deref()).await?;
    let authentication = Arc::new(DeliveryAuthenticationManager::load(&config).await?);
    let uploader = Arc::new(EventUploader::new(&config, Arc::clone(&authentication))?);
    let token_path = arguments
        .control_token_file
        .clone()
        .unwrap_or_else(|| default_control_token_path(arguments.startup_info_file.as_deref()));
    let control = DeliveryControlServer::start(
        token_path,
        arguments.group_readable_control_files,
        authentication,
        Arc::clone(&uploader),
    )
    .await?;
    let worker_result = run_worker(arguments, config, uploader, &control).await;
    let shutdown_result = control.shutdown().await;
    match worker_result {
        Err(error) => Err(error),
        Ok(()) => shutdown_result,
    }
}

async fn run_worker(
    arguments: Arguments,
    config: DeliveryPluginConfig,
    uploader: Arc<EventUploader>,
    control: &DeliveryControlServer,
) -> Result<(), DeliveryPluginError> {
    let _ = uploader.replay_spool().await?;
    let mut plugin = AbyssPlugin::new(config.plugin_id);
    if let Some(endpoint) = config.broker_endpoint {
        plugin = plugin.with_endpoint(endpoint);
    }
    let mut events = plugin.connect().await?;
    let _startup_info = arguments
        .startup_info_file
        .map(|path| {
            WorkerStartupInfoGuard::publish_for_broker(
                &path,
                arguments.broker_pid,
                control.endpoint(),
                control.token_path(),
                arguments.group_readable_control_files,
            )
        })
        .transpose()?;
    while let Some(event) = events.next().await {
        Arc::clone(&uploader).deliver(event?).await?;
    }
    events.take_close().ok_or(AbyssPluginError::UnexpectedEof)?;
    Ok(())
}

fn default_control_token_path(startup_info_file: Option<&std::path::Path>) -> PathBuf {
    startup_info_file
        .and_then(std::path::Path::parent)
        .map_or_else(
            || {
                std::env::var_os("ABYSS_HOME")
                    .map_or_else(|| PathBuf::from(".abyss"), PathBuf::from)
                    .join("runtime")
            },
            std::path::Path::to_owned,
        )
        .join("delivery-control.token")
}
