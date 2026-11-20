//! Command-line interface shared by the native hosts and the routing service.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Read model catalogs and manage model routes")]
pub struct Cli {
    /// Read the catalog JSON directly from standard input.
    #[arg(long)]
    pub catalog_stdin: bool,
    /// Start the system routing worker with the broker startup file.
    #[arg(long, value_name = "STARTUP", allow_hyphen_values = true)]
    pub serve: Option<PathBuf>,
    /// Run a command using this routing profile.
    #[arg(long, value_name = "PATH", allow_hyphen_values = true)]
    pub profile: Option<PathBuf>,
    /// Local management socket (Unix) or named pipe (Windows) of the system worker.
    #[arg(long, conflicts_with = "profile")]
    pub control: Option<PathBuf>,
    /// Previously saved profile to migrate once for the interactive user.
    #[arg(long, requires = "control")]
    pub legacy_profile: Option<PathBuf>,
    #[command(subcommand)]
    pub operation: Option<Operation>,
}

#[derive(Subcommand)]
pub enum Operation {
    #[command(flatten)]
    Control(ControlCommand),
    /// Start a worker for the specified --profile.
    #[cfg(unix)]
    Serve {
        #[arg(allow_hyphen_values = true)]
        startup: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum ControlCommand {
    /// Report the broker process that accepted this worker.
    Status,
    /// Show the current routing state.
    State,
    /// List models for the selection supplied on standard input.
    Models,
    /// Update a harness selection from standard input.
    Select,
    /// Reset the profile's catalog and selections.
    Clear,
    /// Load the catalog source described on standard input.
    Load,
    /// Load an open JSON file from standard input under its supplied name.
    File {
        #[arg(allow_hyphen_values = true)]
        name: PathBuf,
    },
}
