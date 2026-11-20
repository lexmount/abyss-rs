//! Native host command for reading a model-route catalog in the signed-in user's context.

#![expect(
    clippy::multiple_crate_versions,
    reason = "TLS and platform crates are pinned transitively by the workspace HTTP client."
)]

mod catalog;
mod cli;
mod control;
mod rest;
mod routing;
mod source;
mod store;
mod sys;
mod worker;

use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser as _;
use serde::Deserialize;

use crate::cli::{Cli, Operation};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogRequest {
    source: source::Source,
    session: Option<source::NativeSession>,
}

fn run(cli: Cli) -> Result<(), String> {
    let personal = cli.profile.is_some();
    let endpoint = cli
        .profile
        .as_ref()
        .map(|p| sys::personal_endpoint(p))
        .or(cli.control);
    match cli.operation {
        Some(Operation::Control(command)) => {
            let endpoint = endpoint.ok_or("Specify the model routing service endpoint.")?;
            control::request(
                &rest::Client {
                    endpoint: &endpoint,
                    personal,
                },
                cli.legacy_profile.as_deref().or(cli.profile.as_deref()),
                command,
            )
        }
        #[cfg(unix)]
        Some(Operation::Serve { startup }) => {
            let profile = cli.profile.ok_or("Specify a personal routing profile.")?;
            serve(
                startup,
                endpoint.ok_or("Missing control endpoint.")?,
                Some(profile),
            )
        }
        None if cli.serve.is_some() => {
            let startup = cli.serve.ok_or("Missing broker startup file.")?;
            let endpoint = endpoint.unwrap_or_else(|| worker::system_endpoint(&startup));
            serve(startup, endpoint, cli.profile)
        }
        None if cli.catalog_stdin => Ok(write_choices(&source::read_catalog(io::stdin().lock())?)?),
        None => {
            let request: CatalogRequest = read_request()?;
            let catalog = request.source.load(request.session.as_ref())?;
            Ok(write_choices(&catalog)?)
        }
    }
}

fn serve(startup: PathBuf, endpoint: PathBuf, profile: Option<PathBuf>) -> Result<(), String> {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "Cannot start routing worker.")?
        .block_on(worker::run(startup, endpoint, profile))
        .map_err(str::to_owned)
}

const REQUEST_LIMIT: u32 = 64 * 1024;

fn read_request<T: serde::de::DeserializeOwned>() -> Result<T, &'static str> {
    let mut input = Vec::new();
    io::stdin()
        .take(u64::from(REQUEST_LIMIT) + 1)
        .read_to_end(&mut input)
        .map_err(|_| "Cannot read catalog request.")?;
    if input.len() > usize::try_from(REQUEST_LIMIT).unwrap_or(usize::MAX) {
        return Err("Catalog request is too large.");
    }
    serde_json::from_slice(&input).map_err(|_| "Invalid catalog request.")
}

fn write_choices(catalog: &catalog::Catalog) -> Result<(), &'static str> {
    serde_json::to_writer(io::stdout().lock(), &catalog.choices()?)
        .map_err(|_| "Cannot return catalog.")
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
