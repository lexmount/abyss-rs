//! Manage the official routing worker for the per-user explicit proxy.

mod client;
mod import;

#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::{
    fs::{self, OpenOptions},
    io,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use clap::Subcommand;
use hyper::Method;
use serde_json::json;

use crate::{broker::BrokerEndpoint, error::CliError, paths::CliPaths};

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
    client: client::Client,
}

impl Worker {
    fn new(paths: &CliPaths) -> Result<Self, CliError> {
        let profile = paths.root().join("runtime/model-route.json");
        Ok(Self {
            client: client::Client::new(&profile).map_err(CliError::InvalidConfiguration)?,
            executable: std::env::current_exe()?.with_file_name("abyss-model-route"),
            profile,
        })
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
            let value = worker
                .client
                .request(Method::GET, "/v1/model-route/status", Vec::new())
                .ok()?;
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
        let mut command = Command::new(&worker.executable);
        command
            .arg("--profile")
            .arg(&worker.profile)
            .arg("--control")
            .arg(worker.client.endpoint())
            .arg("--serve")
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
        match fs::File::open(&self.profile) {
            Ok(file) => {
                let legacy = import::json(file, 4 * 1024 * 1024)?;
                self.client
                    .request(
                        Method::PUT,
                        "/v1/model-route/profile",
                        serde_json::to_vec(&legacy)?,
                    )
                    .map_err(CliError::InvalidConfiguration)?;
                if let Err(error) = fs::remove_file(&self.profile)
                    && error.kind() != io::ErrorKind::NotFound
                {
                    return Err(error.into());
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let (method, path, body) = match command {
            ModelRouteCommand::State => (Method::GET, "/v1/model-route", None),
            ModelRouteCommand::Clear => (Method::DELETE, "/v1/model-route", None),
            ModelRouteCommand::ImportFile { file } => (
                Method::PUT,
                "/v1/model-route/catalog",
                Some(import::file(&file)?),
            ),
            ModelRouteCommand::ImportUrl { url, sso } => (
                Method::PUT,
                "/v1/model-route/catalog",
                Some(import::service(paths, &url, sso)?),
            ),
            ModelRouteCommand::Models {
                provider,
                credential,
            } => (
                Method::POST,
                "/v1/model-route/models",
                Some(
                    json!({ "provider":provider, "credential":credential, "include_metadata":true }),
                ),
            ),
            ModelRouteCommand::Select {
                harness,
                provider,
                credential,
                model,
            } => (
                Method::PUT,
                "/v1/model-route/selection",
                Some(
                    json!({"harness":harness, "selection":{"provider":provider,"credential":credential,"model":model}}),
                ),
            ),
            ModelRouteCommand::Disable { harness } => (
                Method::PUT,
                "/v1/model-route/selection",
                Some(json!({"harness":harness, "selection":null})),
            ),
        };
        let value = self
            .client
            .request(
                method,
                path,
                body.as_ref()
                    .map(serde_json::to_vec)
                    .transpose()?
                    .unwrap_or_default(),
            )
            .map_err(CliError::InvalidConfiguration)?;
        serde_json::to_writer(io::stdout().lock(), &value)?;
        Ok(())
    }
}
