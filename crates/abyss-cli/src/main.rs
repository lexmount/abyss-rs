//! Cross-platform Abyss endpoint CLI.
//!
//! This binary is the same explicit-proxy control surface on Linux and macOS.
//! It owns user-facing local operations such as terminal SSO,
//! CA trust management, and explicit proxy service control. Product parsing,
//! MITM behavior, and event production remain in shared crates.

mod auth;
mod broker;
mod claude_code;
mod cli;
mod cli_logging;
mod command;
mod credential;
mod delivery;
mod deploy_local;
mod error;
mod filesystem;
mod local_config;
mod network_diagnostics;
mod paths;
mod platform;
mod product_config;
mod runtime;
mod support_bundle;

use std::process::ExitCode;

use clap::Parser as _;

use crate::{cli::Cli, cli_logging::CliLogger, command::CliCommand, paths::CliPaths};

fn main() -> ExitCode {
    let command = std::env::args().nth(1).unwrap_or_else(|| "help".to_owned());
    let logger = CliPaths::from_env()
        .ok()
        .map(|paths| CliLogger::from_paths(&paths));
    if let Some(logger) = &logger {
        logger.record("INFO", &format!("command_started command={command}"));
    }
    let result = CliCommand::from_cli(Cli::parse()).run();
    if let Err(error) = &result
        && let Some(logger) = &logger
    {
        logger.record(
            "ERROR",
            &format!("command_failed command={command} error={error}"),
        );
    }
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("abyss: {error}");
            ExitCode::FAILURE
        }
    }
}
