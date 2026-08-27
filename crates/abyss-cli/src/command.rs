//! Cross-platform endpoint CLI command orchestration.
//!
//! Public commands describe product intent. CA installation, broker lifecycle,
//! broker RPC, and proxy environment setup stay behind this boundary.

use std::{io::Write as _, process::Command as ProcessCommand};

use abyss_agent_hook::{BuiltInHarness, HarnessConfig, HarnessId};
use abyss_terminal_auth::CredentialStore as _;
use chrono::Utc;
use serde_json::Value;

use crate::{
    auth::AuthCommandRunner,
    broker::{BrokerClient, BrokerConnection, ProxyLifecycle},
    claude_code::ClaudeCodeConfigurator,
    cli::{
        Command as ParsedCommand, ConfigCommand, ContextCommand, HarnessCommand, InternalCommand,
        LogCommand, ProxyCommand, RunArgs,
    },
    error::CliError,
    local_config::LocalRuntimePolicy,
    paths::CliPaths,
    platform::platform_adapter,
    product_config::CliProductConfig,
    runtime::{RunningBroker, ensure_started},
    support_bundle::SupportBundleCollector,
};

/// Parsed endpoint command ready for execution.
pub struct CliCommand {
    cli: crate::cli::Cli,
}

impl CliCommand {
    /// Creates an executor from parsed CLI arguments.
    #[must_use]
    pub const fn from_cli(cli: crate::cli::Cli) -> Self {
        Self { cli }
    }

    /// Executes one endpoint CLI operation.
    pub fn run(self) -> Result<(), CliError> {
        let bootstrap = self.runtime_bootstrap();
        let running = if let Some(bootstrap) = bootstrap {
            let paths = CliPaths::from_env()?;
            if self.requires_login_before_bootstrap() {
                require_login_if_configured(&paths)?;
            }
            Some(ensure_started(
                &paths,
                bootstrap.user.as_deref(),
                bootstrap.requested_port,
            )?)
        } else {
            None
        };
        match self.cli.command {
            ParsedCommand::Version => {
                println!("{}", env!("CARGO_PKG_VERSION"));
                Ok(())
            }
            ParsedCommand::Login(args) => AuthCommandRunner::login(&args),
            ParsedCommand::Logout(args) => AuthCommandRunner::logout(&args),
            ParsedCommand::Proxy { command } => ProxyCommandRunner::run(command, running.as_ref()),
            ParsedCommand::Config { command } => {
                ConfigCommandRunner::run(command, running.as_ref())
            }
            ParsedCommand::Log { command } => LogCommandRunner::run(command),
            ParsedCommand::Status(args) => StatusCommandRunner::run(args.broker_api.as_deref()),
            ParsedCommand::Diagnostics(args) => {
                DiagnosticsCommandRunner::run(args.broker_api.as_deref())
            }
            ParsedCommand::Run(args) => run_agent(&args, running.as_ref()),
            ParsedCommand::Internal { command } => run_internal(command),
        }
    }

    fn runtime_bootstrap(&self) -> Option<RuntimeBootstrap> {
        match &self.cli.command {
            ParsedCommand::Login(args) if !args.skip_runtime => Some(RuntimeBootstrap {
                user: None,
                requested_port: None,
            }),
            ParsedCommand::Proxy {
                command: ProxyCommand::Start(args),
            } => Some(RuntimeBootstrap {
                user: args.user.clone(),
                requested_port: args.port,
            }),
            ParsedCommand::Proxy {
                command: ProxyCommand::Env(args),
            } if args.proxy_url.is_none() => Some(RuntimeBootstrap {
                user: None,
                requested_port: None,
            }),
            ParsedCommand::Config { .. } | ParsedCommand::Run(_) => Some(RuntimeBootstrap {
                user: None,
                requested_port: None,
            }),
            _ => None,
        }
    }

    const fn requires_login_before_bootstrap(&self) -> bool {
        matches!(
            &self.cli.command,
            ParsedCommand::Proxy {
                command: ProxyCommand::Start(_)
            } | ParsedCommand::Run(_)
        )
    }
}

struct RuntimeBootstrap {
    user: Option<String>,
    requested_port: Option<u16>,
}

struct ProxyCommandRunner;

impl ProxyCommandRunner {
    fn run(command: ProxyCommand, running: Option<&RunningBroker>) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        match command {
            ProxyCommand::Start(_args) => {
                let running = require_bootstrapped_runtime(running)?;
                let proxy_addr = running.proxy_addr();
                println!("Abyss proxy is running on http://{proxy_addr}.");
                println!("Use `abyss run -- <command>` to launch an agent through it.");
                Ok(())
            }
            ProxyCommand::Stop(args) => {
                platform_adapter().stop_broker(&paths, args.user.as_deref())?;
                println!("Abyss proxy stopped.");
                Ok(())
            }
            ProxyCommand::Env(args) => {
                let proxy_url = if let Some(proxy_url) = args.proxy_url {
                    proxy_url
                } else {
                    format!(
                        "http://{}",
                        require_bootstrapped_runtime(running)?.proxy_addr()
                    )
                };
                let environment = platform_adapter().proxy_environment(&proxy_url);
                std::io::stdout().write_all(environment.as_bytes())?;
                Ok(())
            }
        }
    }
}

struct ConfigCommandRunner;

impl ConfigCommandRunner {
    fn run(command: ConfigCommand, running: Option<&RunningBroker>) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        let running = require_bootstrapped_runtime(running)?;
        let broker = running.endpoint().authenticated_client()?;
        let mut hooks = broker.hooks_config()?;
        match command {
            ConfigCommand::Context { command } => {
                let enabled = matches!(command, ContextCommand::On);
                hooks.harness_usage.config.content.conversation_text = enabled;
                for harness in hooks.harness_usage.config.harnesses.values_mut() {
                    if let Some(content) = &mut harness.content {
                        content.conversation_text = enabled;
                    }
                }
                broker.set_hooks_config(&hooks)?;
                println!("Context capture {}.", context_label(enabled));
                Ok(())
            }
            ConfigCommand::Harness { command } => {
                let (harness, enabled) = match command {
                    HarnessCommand::Enable(args) => (parse_harness(&args.harness)?, true),
                    HarnessCommand::Disable(args) => (parse_harness(&args.harness)?, false),
                };
                let claude_code_configuration =
                    if enabled && matches!(harness, BuiltInHarness::ClaudeCode) {
                        Some(ClaudeCodeConfigurator::from_paths(&paths)?.configure()?)
                    } else {
                        None
                    };
                hooks
                    .harness_usage
                    .config
                    .harnesses
                    .entry(HarnessId::from(harness))
                    .or_insert_with(HarnessConfig::default)
                    .enabled = Some(enabled);
                broker.set_hooks_config(&hooks)?;
                println!(
                    "{} capture {}.",
                    harness_label(harness),
                    if enabled { "enabled" } else { "disabled" }
                );
                if let Some(configuration) = claude_code_configuration {
                    println!(
                        "Claude Code environment configured in {} (CA bundle: {}).",
                        configuration.settings_path().display(),
                        configuration.bundle_path().display()
                    );
                }
                Ok(())
            }
        }
    }
}

struct LogCommandRunner;

impl LogCommandRunner {
    fn run(command: LogCommand) -> Result<(), CliError> {
        match command {
            LogCommand::Dump(args) => Self::dump(args.file, args.broker_api.as_deref()),
        }
    }

    fn dump(path: Option<std::path::PathBuf>, broker_api: Option<&str>) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        let platform = platform_adapter();
        let discovery = BrokerConnection::discover(&paths, platform.as_ref(), broker_api, None);
        let output = SupportBundleCollector::new(paths, discovery).collect(path)?;
        println!("Support bundle written to {}.", output.display());
        Ok(())
    }
}

struct StatusCommandRunner;

struct StatusBroker {
    connection: Option<BrokerConnection>,
    public: Option<BrokerClient>,
    running: bool,
}

impl StatusBroker {
    fn resolve(paths: &CliPaths, broker_api: Option<&str>) -> Result<Self, CliError> {
        let platform = platform_adapter();
        let connection = BrokerConnection::discover(paths, platform.as_ref(), broker_api, None)?;
        let public = connection
            .as_ref()
            .map(BrokerConnection::public_client)
            .transpose()?;
        let running = public
            .as_ref()
            .is_some_and(|broker| broker.health().is_ok());
        Ok(Self {
            connection,
            public,
            running,
        })
    }
}

impl StatusCommandRunner {
    fn run(broker_api: Option<&str>) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        let policy = LocalRuntimePolicy::load(&paths.runtime_policy_file())?;
        let credential = crate::credential::CliCredentialStore::from_paths(&paths)
            .ok()
            .and_then(|store| store.read().ok());
        let auth = credential.as_ref().map_or("logged_out", |credential| {
            if credential.expires_at <= Utc::now() {
                "expired"
            } else {
                "valid"
            }
        });
        let broker = StatusBroker::resolve(&paths, broker_api)?;
        let broker_state = if broker.running {
            "running"
        } else if paths.broker_token_file().exists() {
            "unhealthy"
        } else {
            "stopped"
        };
        let mut proxy = "stopped".to_owned();
        let mut hooks = policy.hooks;
        let mut version = "unknown".to_owned();
        if broker.running {
            if let Some(public) = &broker.public
                && let Ok(status) = public.proxy_status()
                && matches!(&status.lifecycle, ProxyLifecycle::Running)
            {
                let mode = status
                    .mode
                    .as_ref()
                    .map_or("explicit", crate::broker::ProxyMode::as_str);
                let address = status
                    .listen_addr
                    .map_or_else(|| "unknown".to_owned(), |address| address.to_string());
                proxy = format!("{mode}:{address}");
            }
            if let Some(connection) = &broker.connection
                && let Ok(broker) = connection.authenticated_client()
            {
                if let Ok(value) = broker.diagnostics() {
                    value
                        .pointer("/broker/package_version")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .clone_into(&mut version);
                }
                if let Ok(value) = broker.hooks_config() {
                    hooks = value;
                }
            }
        }
        println!(
            "User: {}",
            credential.map_or_else(|| "-".to_owned(), |value| value.user.email)
        );
        println!("Auth: {auth}");
        println!("Broker: {broker_state}");
        println!("Proxy: {proxy}");
        println!("Harnesses:");
        println!("  codex: {}", enabled_label(&hooks, BuiltInHarness::Codex));
        println!(
            "  claude-code: {}",
            enabled_label(&hooks, BuiltInHarness::ClaudeCode)
        );
        println!(
            "Context capture: {}",
            if hooks.harness_usage.config.content.conversation_text {
                "on"
            } else {
                "off"
            }
        );
        println!(
            "Version: cli={}, broker={version}",
            env!("CARGO_PKG_VERSION")
        );
        Ok(())
    }
}

struct DiagnosticsCommandRunner;

impl DiagnosticsCommandRunner {
    fn run(broker_api: Option<&str>) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        let platform = platform_adapter();
        let broker = BrokerConnection::require(&paths, platform.as_ref(), broker_api, None)?
            .authenticated_client()?;
        let response = crate::network_diagnostics::NetworkObservationsResponse::from_value(
            broker.network_observations()?,
        )?;
        response.diagnose_recent().print();
        Ok(())
    }
}

fn run_agent(args: &RunArgs, running: Option<&RunningBroker>) -> Result<(), CliError> {
    let running = require_bootstrapped_runtime(running)?;
    let proxy_addr = running.proxy_addr();
    let mut command = ProcessCommand::new(&args.command[0]);
    let proxy_url = format!("http://{proxy_addr}");
    command
        .args(&args.command[1..])
        .envs(platform_adapter().proxy_environment_variables(&proxy_url));
    let status = command
        .status()
        .map_err(|source| CliError::filesystem("start agent command", &args.command[0], source))?;
    if status.success() {
        return Ok(());
    }
    Err(CliError::Command {
        program: args.command.join(" "),
        status,
        stderr: "agent command exited unsuccessfully".to_owned(),
    })
}

fn require_bootstrapped_runtime(
    running: Option<&RunningBroker>,
) -> Result<&RunningBroker, CliError> {
    running.ok_or_else(|| {
        CliError::InvalidConfiguration(
            "the command requires the CLI product runtime bootstrap".to_owned(),
        )
    })
}

fn require_login_if_configured(paths: &CliPaths) -> Result<(), CliError> {
    let product_config = CliProductConfig::load(&paths.product_config_file())?;
    if !product_config.requires_terminal_login() {
        return Ok(());
    }
    let store = crate::credential::CliCredentialStore::from_paths(paths)?;
    let credential = store.read().map_err(|_| {
        CliError::InvalidConfiguration(
            "this command requires login; run `abyss login` first".to_owned(),
        )
    })?;
    if credential.expires_at <= Utc::now() {
        return Err(CliError::InvalidConfiguration(
            "this command requires login; run `abyss login` first".to_owned(),
        ));
    }
    Ok(())
}

fn run_internal(command: InternalCommand) -> Result<(), CliError> {
    match command {
        InternalCommand::CaInstall(args) => platform_adapter().install_ca_at(&args.ca_dir),
    }
}

fn parse_harness(value: &str) -> Result<BuiltInHarness, CliError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "codex" => Ok(BuiltInHarness::Codex),
        "claude-code" | "claude-cli" => Ok(BuiltInHarness::ClaudeCode),
        _ => Err(CliError::InvalidConfiguration(
            "Harness must be codex or claude-code".to_owned(),
        )),
    }
}

const fn harness_label(harness: BuiltInHarness) -> &'static str {
    match harness {
        BuiltInHarness::Codex => "codex",
        BuiltInHarness::ClaudeCode => "claude-code",
        BuiltInHarness::ClaudeDesktop => "claude-desktop",
        _ => "unknown",
    }
}

const fn context_label(enabled: bool) -> &'static str {
    if enabled { "enabled" } else { "disabled" }
}

fn enabled_label(hooks: &abyss_agent_hook::HooksConfig, agent: BuiltInHarness) -> &'static str {
    if !hooks.harness_usage.enabled || !hooks.harness_usage.config.enabled_for_harness(agent.id()) {
        "disabled"
    } else {
        "enabled"
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::CliCommand;

    #[test]
    fn runtime_flows_share_the_delivery_worker_bootstrap() {
        for arguments in [
            vec!["abyss", "login"],
            vec!["abyss", "proxy", "start"],
            vec!["abyss", "proxy", "env"],
            vec!["abyss", "config", "context", "off"],
            vec!["abyss", "run", "--", "true"],
        ] {
            let command = CliCommand::from_cli(
                crate::cli::Cli::try_parse_from(&arguments).expect("runtime command should parse"),
            );
            assert!(
                command.runtime_bootstrap().is_some(),
                "runtime command should bootstrap the fixed worker: {arguments:?}"
            );
        }
    }

    #[test]
    fn observational_and_stopping_flows_do_not_create_a_runtime() {
        for arguments in [
            vec!["abyss", "version"],
            vec!["abyss", "login", "--skip-runtime"],
            vec!["abyss", "logout"],
            vec!["abyss", "proxy", "stop"],
            vec![
                "abyss",
                "proxy",
                "env",
                "--proxy-url",
                "http://127.0.0.1:1234",
            ],
            vec!["abyss", "status"],
            vec!["abyss", "diagnostics"],
            vec!["abyss", "log", "dump"],
        ] {
            let command = CliCommand::from_cli(
                crate::cli::Cli::try_parse_from(&arguments)
                    .expect("non-starting command should parse"),
            );
            assert!(
                command.runtime_bootstrap().is_none(),
                "non-starting command must not create a runtime: {arguments:?}"
            );
        }
    }

    #[test]
    fn proxy_start_bootstrap_carries_existing_user_and_port_options() {
        let command = CliCommand::from_cli(
            crate::cli::Cli::try_parse_from([
                "abyss", "proxy", "start", "--user", "operator", "--port", "30123",
            ])
            .expect("proxy start should parse"),
        );

        let bootstrap = command
            .runtime_bootstrap()
            .expect("proxy start should bootstrap the runtime");
        assert_eq!(bootstrap.user.as_deref(), Some("operator"));
        assert_eq!(bootstrap.requested_port, Some(30123));
    }
}
