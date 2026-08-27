//! Minimal bootstrap command line for `abyss-broker`.
//!
//! Product behavior is configured by one startup TOML file. The remaining
//! arguments are broker-control bootstrap endpoints used by wrappers and tests;
//! they do not duplicate audit, diagnostics, CA, proxy, or policy settings.

use std::{net::SocketAddr, path::PathBuf};

use clap::{Parser, ValueHint};

pub const DEFAULT_API_ENDPOINT: &str = "127.0.0.1:0";

/// Top-level CLI parsed by `clap`.
#[derive(Debug, Parser)]
#[command(name = "abyss-broker")]
#[command(about = "Run the cross-platform Abyss broker proxy.")]
pub struct Cli {
    #[arg(
        long,
        default_value = DEFAULT_API_ENDPOINT,
        value_parser = parse_loopback_socket_addr,
        help = "Local REST API endpoint for broker control."
    )]
    pub api: SocketAddr,

    #[arg(
        long,
        value_name = "CONFIG_FILE",
        value_hint = ValueHint::FilePath,
        help = "Broker startup TOML file; otherwise the platform-local file or built-ins are used."
    )]
    pub config: Option<PathBuf>,

    #[arg(
        long,
        value_name = "TOKEN_FILE",
        value_hint = ValueHint::FilePath,
        help = "Bearer token file used by the platform wrapper for REST control."
    )]
    pub auth_token_file: Option<PathBuf>,

    #[arg(
        long,
        value_name = "STARTUP_INFO_FILE",
        value_hint = ValueHint::FilePath,
        help = "Optional JSON file written after the broker binds its REST API."
    )]
    pub startup_info_file: Option<PathBuf>,
}

impl Cli {
    /// Parses command-line arguments from the process environment.
    #[must_use]
    pub fn parse() -> Self {
        <Self as Parser>::parse()
    }
}

fn parse_loopback_socket_addr(value: &str) -> Result<SocketAddr, String> {
    let address = value
        .parse::<SocketAddr>()
        .map_err(|error| format!("invalid socket address: {error}"))?;
    if !address.ip().is_loopback() {
        return Err("broker endpoint must use a loopback address".to_owned());
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use clap::Parser as _;

    use super::{Cli, DEFAULT_API_ENDPOINT, parse_loopback_socket_addr};

    #[test]
    fn endpoint_parser_accepts_loopback_address() {
        assert!(parse_loopback_socket_addr("127.0.0.1:18190").is_ok());
        assert!(parse_loopback_socket_addr("[::1]:18190").is_ok());
    }

    #[test]
    fn endpoint_parser_rejects_non_loopback_address() {
        let error =
            parse_loopback_socket_addr("0.0.0.0:18190").expect_err("wildcard bind is rejected");
        assert!(error.contains("loopback"));
    }

    #[test]
    fn config_file_is_the_only_product_configuration_argument() {
        let cli = Cli::try_parse_from([
            "abyss-broker",
            "--config",
            "/tmp/broker-config.toml",
            "--api",
            "127.0.0.1:19090",
        ])
        .expect("bootstrap arguments should parse");

        assert_eq!(cli.config, Some(PathBuf::from("/tmp/broker-config.toml")));
        assert_eq!(cli.api.to_string(), "127.0.0.1:19090");
    }

    #[test]
    fn startup_file_is_optional() {
        let cli = Cli::try_parse_from(["abyss-broker"])
            .expect("built-in configuration should not require arguments");

        assert_eq!(cli.api.to_string(), DEFAULT_API_ENDPOINT);
        assert!(cli.config.is_none());
    }

    #[test]
    fn removed_per_setting_arguments_are_rejected() {
        for argument in ["--ca-dir", "--proxy-mode", "--listen", "--flow-socket"] {
            let error = Cli::try_parse_from(["abyss-broker", argument, "value"])
                .expect_err("per-setting argument should not remain in the public CLI");
            assert!(
                error.to_string().contains("unexpected argument"),
                "unexpected clap error for {argument}: {error}"
            );
        }
    }
}
