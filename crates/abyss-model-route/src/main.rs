//! Start the model-routing worker and its local HTTP management service.

#![expect(
    clippy::multiple_crate_versions,
    reason = "TLS dependencies are pinned transitively by the workspace."
)]

mod catalog;
mod rest;
mod routing;
mod store;
mod sys;
mod worker;

use clap::Parser;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(version, about = "Serve model routing for a running broker")]
struct Args {
    /// Startup information published by the broker.
    #[arg(long, value_name = "STARTUP")]
    serve: PathBuf,
    /// Personal profile location used to derive the state directory.
    #[arg(long, requires = "control")]
    profile: Option<PathBuf>,
    /// Local REST endpoint. Defaults to the platform system endpoint.
    #[arg(long)]
    control: Option<PathBuf>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let endpoint = args
        .control
        .unwrap_or_else(|| worker::system_endpoint(&args.serve));
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "Cannot start routing worker.")
        .and_then(|rt| rt.block_on(worker::run(args.serve, endpoint, args.profile)));
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
