//! Standalone data-query CLI; independent of the broker and endpoint runtime.

mod args;
mod auth;
mod budget;
mod config;
mod credentials;
mod error;
mod output;
mod run;

use args::Cli;
use clap::Parser as _;
use std::{
    io::{self, Write as _},
    process::ExitCode,
};

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) =>
        {
            return if error.print().is_ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            };
        }
        Err(_) => {
            let error = error::QueryError::Config(
                "invalid command arguments; use --help for the command grammar",
            );
            let _result = writeln!(io::stderr().lock(), "{}", error.diagnostic());
            return ExitCode::from(2);
        }
    };
    match run::execute(&cli).and_then(|output| output.write(cli.format)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error::QueryError::Io(error)) if error.kind() == io::ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(error) => {
            let _result = writeln!(io::stderr().lock(), "{}", error.diagnostic());
            ExitCode::from(error.code().1)
        }
    }
}
