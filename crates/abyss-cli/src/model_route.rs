//! Manage the official routing worker for the per-user explicit proxy.

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::{
    fs::{self, OpenOptions},
    io::{self, Write as _},
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use abyss_terminal_auth::CredentialStore as _;
use clap::Subcommand;
use serde_json::{Value, json};

use crate::{
    broker::BrokerEndpoint, credential::CliCredentialStore, error::CliError, paths::CliPaths,
};

#[derive(Debug, Subcommand)]
pub enum ModelRouteCommand {
    /// Show available providers, credentials, model suggestions and current selections.
    State,
    /// Import a local JSON catalog or refresh a previously imported file.
    ImportFile { file: PathBuf },
    /// Import a catalog from a configuration service.
    ImportUrl {
        url: String,
        /// Send the current terminal login to its issuing origin.
        #[arg(long)]
        sso: bool,
    },
    /// Discover models available to a provider credential.
    Models {
        provider: String,
        credential: String,
    },
    /// Set the provider, credential and model for one harness.
    Select {
        harness: String,
        provider: String,
        credential: String,
        model: String,
    },
    /// Disable routing for one harness.
    Disable { harness: String },
    /// Clear the catalog and all selections.
    Clear,
}

pub struct Worker {
    profile: PathBuf,
    executable: PathBuf,
}

impl Worker {
    fn new(paths: &CliPaths) -> Result<Self, CliError> {
        let executable = std::env::current_exe()?.with_file_name("abyss-model-route");
        Ok(Self {
            profile: paths.root().join("runtime/model-route.json"),
            executable,
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.executable);
        command.arg("--profile").arg(&self.profile);
        command
    }

    pub fn configured(paths: &CliPaths) -> bool {
        paths.root().join("runtime/model-route.routes").is_dir()
    }

    /// Serializes startup across simultaneous CLI commands. The worker publishes
    /// its control socket only after the inspector handshake completes.
    pub fn ensure(paths: &CliPaths, broker: &BrokerEndpoint) -> Result<Self, CliError> {
        let worker = Self::new(paths)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(worker.profile.with_extension("start.lock"))?;
        lock.lock()?;
        let current = || {
            let reply = worker
                .command()
                .arg("status")
                .stdin(Stdio::null())
                .stderr(Stdio::null())
                .output()
                .ok()?;
            let value: Value = serde_json::from_slice(&reply.stdout).ok()?;
            value["broker_pid"].as_u64()
        };
        let started = Instant::now();
        while let Some(pid) = current() {
            if pid == u64::from(broker.pid()) {
                return Ok(worker);
            }
            if started.elapsed() >= Duration::from_secs(5) {
                return Err(CliError::InvalidConfiguration(
                    "previous routing worker is still connected".into(),
                ));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        let mut command = worker.command();
        command
            .arg("serve")
            .arg(paths.broker_startup_info_file())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        #[cfg(unix)]
        command.process_group(0);
        let mut child = command
            .spawn()
            .map_err(|e| CliError::filesystem("launch routing worker", &worker.executable, e))?;
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if current() == Some(u64::from(broker.pid())) {
                return Ok(worker);
            }
            if let Some(status) = child.try_wait()? {
                return Err(CliError::InvalidConfiguration(format!(
                    "routing worker exited with {status} for broker {}",
                    broker.pid()
                )));
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        child.kill()?;
        child.wait()?;
        Err(CliError::InvalidConfiguration(
            "routing worker did not become ready".into(),
        ))
    }

    pub fn run(&self, paths: &CliPaths, command: ModelRouteCommand) -> Result<(), CliError> {
        let (operation, input) = match command {
            ModelRouteCommand::State => ("state", None),
            ModelRouteCommand::Clear => ("clear", None),
            ModelRouteCommand::ImportFile { file } => (
                "load",
                Some(json!({"source":{"type":"file","path":fs::canonicalize(file)?}})),
            ),
            ModelRouteCommand::ImportUrl { url, sso } => {
                let mut input = json!({"source":{"type":"service","url":url,"sso":sso}});
                if sso {
                    let credential = CliCredentialStore::from_paths(paths)?.read()?;
                    if credential.expires_at <= jiff::Timestamp::now() {
                        return Err(CliError::InvalidConfiguration(
                            "sign in again to import this catalog".into(),
                        ));
                    }
                    input["session"] =
                        json!({"origin":credential.control_plane,"bearer":credential.token});
                }
                ("load", Some(input))
            }
            ModelRouteCommand::Models {
                provider,
                credential,
            } => (
                "models",
                Some(json!({ "provider":provider,"credential":credential,"include_metadata":true})),
            ),
            ModelRouteCommand::Select {
                harness,
                provider,
                credential,
                model,
            } => (
                "select",
                Some(
                    json!({"harness":harness,"selection":{"provider":provider,"credential":credential,"model":model}}),
                ),
            ),
            ModelRouteCommand::Disable { harness } => (
                "select",
                Some(json!({"harness":harness,"selection":Value::Null})),
            ),
        };
        let mut child = self
            .command()
            .arg(operation)
            .stdin(Stdio::piped())
            .spawn()?;
        if let Some(input) = input {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| io::Error::other("missing routing worker stdin"))?;
            stdin.write_all(&serde_json::to_vec(&input)?)?;
        }
        drop(child.stdin.take());
        let status = child.wait()?;
        if status.success() {
            Ok(())
        } else {
            Err(CliError::InvalidConfiguration(format!(
                "model route {operation} failed"
            )))
        }
    }
}
