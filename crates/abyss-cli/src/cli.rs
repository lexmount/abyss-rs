//! Stable product command-line shape for the Abyss endpoint CLI.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueHint};

/// User-facing endpoint command.
#[derive(Debug, Parser)]
#[command(name = "abyss", version, about = "Manage the Abyss endpoint.")]
pub struct Cli {
    /// Product operation.
    #[command(subcommand)]
    pub command: Command,
}

/// Existing commands exposed by the cross-platform CLI.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Print the installed Abyss CLI version.
    Version,
    /// Sign this endpoint user in through the browser-based terminal flow.
    Login(LoginArgs),
    /// Revoke the endpoint credential and sign out.
    Logout(LogoutArgs),
    /// Manage the local explicit proxy lifecycle.
    Proxy {
        /// Proxy operation.
        #[command(subcommand)]
        command: ProxyCommand,
    },
    /// Change local capture policy.
    Config {
        /// Configuration operation.
        #[command(subcommand)]
        command: ConfigCommand,
    },
    /// Create a redacted support bundle.
    Log {
        /// Log operation.
        #[command(subcommand)]
        command: LogCommand,
    },
    /// Show the combined endpoint and broker status.
    Status(StatusArgs),
    /// Deploy and manage the local SQLite+FTS environment.
    DeployLocal {
        /// Local deployment operation.
        #[command(subcommand)]
        command: DeployLocalCommand,
    },
    /// Diagnose the latest Agent network request from local broker observations.
    Diagnostics(DiagnosticsArgs),
    /// Run a child process with the explicit proxy configured.
    Run(RunArgs),
    /// Internal trust-store operation retained for the Linux privilege boundary.
    #[command(hide = true)]
    Internal {
        /// Internal operation.
        #[command(subcommand)]
        command: InternalCommand,
    },
}

/// Local SQLite+FTS deployment operations.
#[derive(Debug, Subcommand)]
pub enum DeployLocalCommand {
    /// Install missing components and start the complete local environment.
    Start,
    /// Stop the proxy, dashboard, and backend while preserving local data.
    Stop,
    /// Report backend, dashboard, and proxy health.
    Status,
}

/// Terminal login options. The control-plane URL is normally supplied by
/// `ABYSS_CONTROL_PLANE`; the flag remains useful for isolated deployments.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Control-plane base URL override.
    #[arg(long, env = "ABYSS_CONTROL_PLANE")]
    pub control_plane: Option<String>,
    /// Maximum browser SSO wait time.
    #[arg(long, default_value_t = 600)]
    pub timeout_seconds: u64,
    /// Override the server-recommended polling interval.
    #[arg(long)]
    pub poll_interval_seconds: Option<u64>,
    /// Broker REST endpoint override for isolated tests.
    #[arg(long, hide = true)]
    pub broker_api: Option<String>,
    /// Broker token file override for isolated tests.
    #[arg(long, hide = true, value_name = "TOKEN_FILE", value_hint = ValueHint::FilePath)]
    pub broker_token_file: Option<PathBuf>,
    /// Skip runtime setup in protocol-only tests.
    #[arg(long, hide = true)]
    pub skip_runtime: bool,
}

/// Logout options.
#[derive(Debug, Args)]
pub struct LogoutArgs {
    /// Control-plane URL override.
    #[arg(long)]
    pub control_plane: Option<String>,
    /// Broker REST endpoint override for isolated tests.
    #[arg(long, hide = true)]
    pub broker_api: Option<String>,
    /// Broker token file override for isolated tests.
    #[arg(long, hide = true, value_name = "TOKEN_FILE", value_hint = ValueHint::FilePath)]
    pub broker_token_file: Option<PathBuf>,
}

/// Explicit proxy operations.
#[derive(Debug, Subcommand)]
pub enum ProxyCommand {
    /// Prepare CA trust and start the per-user broker service.
    Start(StartArgs),
    /// Stop the per-user broker service.
    Stop(StopArgs),
    /// Print shell exports for the explicit proxy.
    Env(EnvArgs),
}

/// Proxy start options.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Linux account used as the systemd template instance.
    #[arg(long, hide = true)]
    pub user: Option<String>,
    /// Loopback proxy port. Omit it to let the operating system choose one.
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,
}

/// Proxy stop options.
#[derive(Debug, Args)]
pub struct StopArgs {
    /// Linux account used as the systemd template instance.
    #[arg(long, hide = true)]
    pub user: Option<String>,
}

/// Capture configuration operations.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Enable or disable prompt and response context capture.
    Context {
        /// Enable plaintext context capture.
        #[command(subcommand)]
        command: ContextCommand,
    },
    /// Enable or disable one supported Harness.
    #[command(alias = "agent")]
    Harness {
        /// Harness configuration operation.
        #[command(subcommand)]
        command: HarnessCommand,
    },
}

/// Context capture operations.
#[derive(Debug, Subcommand)]
pub enum ContextCommand {
    /// Upload plaintext prompt and response context.
    On,
    /// Upload usage metadata without plaintext context.
    Off,
}

/// Harness capture operations.
#[derive(Debug, Subcommand)]
pub enum HarnessCommand {
    /// Enable one Harness.
    Enable(HarnessArgs),
    /// Disable one Harness.
    Disable(HarnessArgs),
}

/// Harness selector.
#[derive(Debug, Args)]
pub struct HarnessArgs {
    /// Harness name: codex or claude-code.
    pub harness: String,
}

/// Support log operations.
#[derive(Debug, Subcommand)]
pub enum LogCommand {
    /// Write a redacted support bundle.
    Dump(LogDumpArgs),
}

/// Support bundle destination.
#[derive(Debug, Args)]
pub struct LogDumpArgs {
    /// Output file. Defaults below the platform CLI state log directory.
    #[arg(short = 'f', long, value_name = "PATH", value_hint = ValueHint::FilePath)]
    pub file: Option<PathBuf>,
    /// Broker API override for isolated tests.
    #[arg(long, hide = true)]
    pub broker_api: Option<String>,
}

/// Status options kept private to the product command surface.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Broker API override for isolated tests.
    #[arg(long, hide = true)]
    pub broker_api: Option<String>,
}

/// Network diagnostics options kept private to the product command surface.
#[derive(Debug, Args)]
pub struct DiagnosticsArgs {
    /// Broker API override for isolated tests.
    #[arg(long, hide = true)]
    pub broker_api: Option<String>,
}

/// Child process execution options.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Command and arguments to execute with the proxy environment.
    #[arg(required = true, trailing_var_arg = true)]
    pub command: Vec<String>,
}

/// Hidden installer operations retained for Linux compatibility.
#[derive(Debug, Subcommand)]
pub enum InternalCommand {
    /// Install the already-generated CA into the machine trust store.
    CaInstall(CaInstallArgs),
}

/// Internal CA operation options.
#[derive(Debug, Args)]
pub struct CaInstallArgs {
    /// Explicit CA material directory.
    #[arg(long, value_name = "CA_DIR", value_hint = ValueHint::DirPath)]
    pub ca_dir: PathBuf,
}

#[derive(Debug, Args)]
pub struct EnvArgs {
    /// Explicit proxy endpoint. Defaults to the running broker's endpoint.
    #[arg(long)]
    pub proxy_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory as _, Parser as _};

    use super::{Command, ConfigCommand, ContextCommand, DeployLocalCommand, ProxyCommand};

    #[test]
    fn parses_version_command() {
        let cli =
            super::Cli::try_parse_from(["abyss", "version"]).expect("version command should parse");
        assert!(matches!(cli.command, Command::Version));
    }

    #[test]
    fn parses_documented_commands() {
        let login = super::Cli::try_parse_from(["abyss", "login"]).expect("login should parse");
        assert!(matches!(login.command, Command::Login(_)));

        let context = super::Cli::try_parse_from(["abyss", "config", "context", "off"])
            .expect("context command should parse");
        let Command::Config { command } = context.command else {
            panic!("expected config command");
        };
        assert!(matches!(
            command,
            ConfigCommand::Context {
                command: ContextCommand::Off
            }
        ));

        let proxy = super::Cli::try_parse_from(["abyss", "proxy", "start"])
            .expect("proxy command should parse");
        let Command::Proxy { command } = proxy.command else {
            panic!("expected proxy command");
        };
        assert!(matches!(command, ProxyCommand::Start(_)));

        let deploy = super::Cli::try_parse_from(["abyss", "deploy-local", "start"])
            .expect("local deployment command should parse");
        let Command::DeployLocal { command } = deploy.command else {
            panic!("expected local deployment command");
        };
        assert!(matches!(command, DeployLocalCommand::Start));
    }

    #[test]
    fn parses_run_command_with_arguments() {
        let cli = super::Cli::try_parse_from(["abyss", "run", "--", "codex", "--version"])
            .expect("run command should parse");
        let Command::Run(args) = cli.command else {
            panic!("expected run command");
        };
        assert_eq!(args.command, ["codex", "--version"]);
    }

    #[test]
    fn parses_custom_proxy_port() {
        let cli = super::Cli::try_parse_from(["abyss", "proxy", "start", "--port", "30123"])
            .expect("proxy port should parse");
        let Command::Proxy { command } = cli.command else {
            panic!("expected proxy command");
        };
        let ProxyCommand::Start(args) = command else {
            panic!("expected proxy start command");
        };
        assert_eq!(args.port, Some(30123));
    }

    #[test]
    fn public_help_preserves_the_existing_command_surface() {
        let help = super::Cli::command().render_long_help().to_string();

        for command in [
            "version",
            "login",
            "logout",
            "proxy",
            "config",
            "log",
            "status",
            "deploy-local",
            "diagnostics",
            "run",
        ] {
            assert!(
                help.lines()
                    .any(|line| line.trim_start().starts_with(command)),
                "public help should contain `{command}`; help={help}"
            );
        }
        assert!(
            !help
                .lines()
                .any(|line| line.trim_start().starts_with("internal")),
            "internal installer operations must remain hidden; help={help}"
        );
        for out_of_scope_command in ["interception", "dashboard", "driver", "service", "ca"] {
            assert!(
                !help
                    .lines()
                    .any(|line| line.trim_start().starts_with(out_of_scope_command)),
                "public help must not add `{out_of_scope_command}`; help={help}"
            );
        }
    }

    #[test]
    fn all_existing_public_command_forms_parse() {
        let commands: &[&[&str]] = &[
            &["abyss", "version"],
            &["abyss", "login"],
            &["abyss", "logout"],
            &["abyss", "proxy", "start"],
            &["abyss", "proxy", "stop"],
            &["abyss", "proxy", "env"],
            &["abyss", "config", "context", "on"],
            &["abyss", "config", "context", "off"],
            &["abyss", "config", "agent", "enable", "codex"],
            &["abyss", "config", "agent", "enable", "claude-code"],
            &["abyss", "config", "agent", "disable", "codex"],
            &["abyss", "config", "agent", "disable", "claude-code"],
            &["abyss", "log", "dump"],
            &["abyss", "log", "dump", "-f", "support.zip"],
            &["abyss", "status"],
            &["abyss", "deploy-local", "start"],
            &["abyss", "deploy-local", "stop"],
            &["abyss", "deploy-local", "status"],
            &["abyss", "diagnostics"],
            &["abyss", "run", "--", "codex", "--version"],
        ];

        for command in commands {
            super::Cli::try_parse_from(*command)
                .unwrap_or_else(|error| panic!("command should parse: {command:?}: {error}"));
        }
    }
}
