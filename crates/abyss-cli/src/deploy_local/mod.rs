//! CLI-managed installation and lifecycle of the local SQLite+FTS environment.
//!
//! Public commands see one deployment boundary. Artifact sources, generated
//! product configuration, process ownership, and platform paths stay internal.

mod artifacts;
mod config;
mod process;

use std::{
    net::{Ipv4Addr, SocketAddrV4, TcpListener},
    time::Duration,
};

use artifacts::{ArtifactInstaller, DashboardArtifact, RuntimeArtifacts};
use config::{
    DeploymentState, LocalCredentials, LocalPaths, validate_product_config_ownership,
    write_product_config,
};
use process::{DeploymentOperationLock, ManagedService, ServiceCommand, ServiceStatus};

use crate::{error::CliError, paths::CliPaths};

const BACKEND_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
const DASHBOARD_HOST: Ipv4Addr = Ipv4Addr::LOCALHOST;

pub struct LocalDeployment {
    cli_paths: CliPaths,
    paths: LocalPaths,
    health_client: reqwest::blocking::Client,
}

pub struct StartedLocalServices {
    state: DeploymentState,
    backend_started: bool,
    dashboard_started: bool,
}

pub struct LocalDeploymentStatus {
    backend: ServiceStatus,
    dashboard: ServiceStatus,
    backend_url: Option<String>,
    dashboard_url: Option<String>,
}

impl LocalDeployment {
    pub fn from_paths(cli_paths: CliPaths) -> Result<Self, CliError> {
        validate_state_root(cli_paths.root())?;
        let health_client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(1))
            .timeout(Duration::from_secs(2))
            .no_proxy()
            .build()
            .map_err(CliError::LocalArtifactRequest)?;
        let paths = LocalPaths::from_cli(&cli_paths);
        Ok(Self {
            cli_paths,
            paths,
            health_client,
        })
    }

    pub fn start(&self) -> Result<StartedLocalServices, CliError> {
        self.paths.ensure_directories()?;
        let _operation = DeploymentOperationLock::acquire(&self.paths)?;
        validate_product_config_ownership(&self.cli_paths)?;
        let artifacts = ArtifactInstaller::new(&self.paths)?.ensure()?;
        let credentials = LocalCredentials::ensure(&self.paths)?;
        let backend = ManagedService::backend(&self.paths);
        let dashboard = ManagedService::dashboard(&self.paths);
        let mut previous = DeploymentState::load(&self.paths)?;
        if previous
            .as_ref()
            .is_some_and(|state| !state.uses_current_artifacts())
        {
            dashboard.stop()?;
            backend.stop()?;
            previous = None;
        } else if previous.is_none() {
            dashboard.stop()?;
            backend.stop()?;
        }

        let previous_backend_port = previous.as_ref().map(|state| state.backend_port);
        let backend_port =
            self.ensure_backend(&backend, &artifacts, &credentials, previous_backend_port)?;
        let backend_started = backend_port.started;
        let backend_port = backend_port.port;

        let previous_dashboard_port = previous.as_ref().map(|state| state.dashboard_port);
        let backend_address_changed =
            previous_backend_port.is_some_and(|port| port != backend_port);
        if backend_address_changed {
            dashboard.stop()?;
        }
        let dashboard_result = self.ensure_dashboard(
            &dashboard,
            &artifacts,
            backend_port,
            previous_dashboard_port,
        );
        let dashboard_port = match dashboard_result {
            Ok(result) => result,
            Err(error) => {
                if backend_started {
                    drop(backend.stop());
                }
                return Err(error);
            }
        };
        let state = DeploymentState::new(backend_port, dashboard_port.port);
        if let Err(error) = state
            .write(&self.paths)
            .and_then(|()| write_product_config(&self.cli_paths, &self.paths, &state))
        {
            if dashboard_port.started {
                drop(dashboard.stop());
            }
            if backend_started {
                drop(backend.stop());
            }
            return Err(error);
        }
        Ok(StartedLocalServices {
            state,
            backend_started,
            dashboard_started: dashboard_port.started,
        })
    }

    pub fn rollback(&self, started: &StartedLocalServices) {
        if self.paths.ensure_directories().is_err() {
            return;
        }
        let Ok(_operation) = DeploymentOperationLock::acquire(&self.paths) else {
            return;
        };
        if started.dashboard_started {
            drop(ManagedService::dashboard(&self.paths).stop());
        }
        if started.backend_started {
            drop(ManagedService::backend(&self.paths).stop());
        }
    }

    pub fn stop(&self) -> Result<(), CliError> {
        if !self.paths.root().exists() {
            return Ok(());
        }
        self.paths.ensure_directories()?;
        let _operation = DeploymentOperationLock::acquire(&self.paths)?;
        ManagedService::dashboard(&self.paths).stop()?;
        ManagedService::backend(&self.paths).stop()?;
        Ok(())
    }

    pub fn status(&self) -> Result<LocalDeploymentStatus, CliError> {
        if !self.paths.root().exists() {
            return Ok(LocalDeploymentStatus {
                backend: ServiceStatus::Stopped,
                dashboard: ServiceStatus::Stopped,
                backend_url: None,
                dashboard_url: None,
            });
        }
        self.paths.ensure_directories()?;
        let _operation = DeploymentOperationLock::acquire(&self.paths)?;
        let Some(state) = DeploymentState::load(&self.paths)? else {
            return Ok(LocalDeploymentStatus {
                backend: ServiceStatus::Stopped,
                dashboard: ServiceStatus::Stopped,
                backend_url: None,
                dashboard_url: None,
            });
        };
        let backend_url = state.backend_url();
        let dashboard_url = state.dashboard_url();
        let backend = ManagedService::backend(&self.paths)
            .status(&self.health_client, &format!("{backend_url}/readyz"))?;
        let dashboard = ManagedService::dashboard(&self.paths)
            .status(&self.health_client, &format!("{dashboard_url}/healthz"))?;
        Ok(LocalDeploymentStatus {
            backend,
            dashboard,
            backend_url: Some(backend_url),
            dashboard_url: Some(dashboard_url),
        })
    }

    fn ensure_backend(
        &self,
        service: &ManagedService,
        artifacts: &RuntimeArtifacts,
        credentials: &LocalCredentials,
        previous_port: Option<u16>,
    ) -> Result<PortStart, CliError> {
        if let Some(port) = previous_port {
            let health_url = format!("http://{}/readyz", socket_address(BACKEND_HOST, port));
            match service.status(&self.health_client, &health_url)? {
                ServiceStatus::Running { .. } => {
                    return Ok(PortStart {
                        port,
                        started: false,
                    });
                }
                ServiceStatus::Stopped => {}
                unhealthy @ ServiceStatus::Unhealthy { .. } => {
                    return Err(CliError::InvalidConfiguration(format!(
                        "local backend is {}; run `abyss deploy-local stop` before retrying",
                        unhealthy.label()
                    )));
                }
            }
        }
        let port = available_port(previous_port, None)?;
        let address = socket_address(BACKEND_HOST, port);
        let mut command = ServiceCommand::new(
            artifacts.backend.as_os_str().to_owned(),
            artifacts.backend.clone(),
        );
        command
            .environment("ABYSS_BACKEND_ADDR", address.to_string())
            .environment("ABYSS_BACKEND_ENV", "local")
            .environment(
                "ABYSS_BACKEND_DATABASE_URL",
                self.paths.database_file().into_os_string(),
            )
            .environment(
                "ABYSS_BACKEND_API_TOKEN_SHA256",
                credentials.token_sha256.clone(),
            )
            .environment("ABYSS_BACKEND_RUN_MIGRATIONS", "true");
        let health_url = format!("http://{address}/readyz");
        let disposition = service.start(&command, &self.health_client, &health_url)?;
        Ok(PortStart {
            port,
            started: disposition.was_started(),
        })
    }

    fn ensure_dashboard(
        &self,
        service: &ManagedService,
        artifacts: &RuntimeArtifacts,
        backend_port: u16,
        previous_port: Option<u16>,
    ) -> Result<PortStart, CliError> {
        if let Some(port) = previous_port {
            let health_url = format!("http://{}/healthz", socket_address(DASHBOARD_HOST, port));
            match service.status(&self.health_client, &health_url)? {
                ServiceStatus::Running { .. } => {
                    return Ok(PortStart {
                        port,
                        started: false,
                    });
                }
                ServiceStatus::Stopped => {}
                unhealthy @ ServiceStatus::Unhealthy { .. } => {
                    return Err(CliError::InvalidConfiguration(format!(
                        "local dashboard is {}; run `abyss deploy-local stop` before retrying",
                        unhealthy.label()
                    )));
                }
            }
        }
        let port = available_port(previous_port, Some(backend_port))?;
        let address = socket_address(DASHBOARD_HOST, port);
        let mut command = match &artifacts.dashboard {
            DashboardArtifact::Direct(path) => {
                ServiceCommand::new(path.as_os_str().to_owned(), path.clone())
            }
            DashboardArtifact::NodeScript { node, script } => {
                let mut command = ServiceCommand::new(node.clone(), script.clone());
                command.argument(script.as_os_str().to_owned());
                command
            }
        };
        command
            .argument("--host")
            .argument(DASHBOARD_HOST.to_string())
            .argument("--port")
            .argument(port.to_string())
            .argument("--backend")
            .argument(format!(
                "http://{}",
                socket_address(BACKEND_HOST, backend_port)
            ))
            .argument("--token-file")
            .argument(self.paths.token_file().into_os_string());
        let health_url = format!("http://{address}/healthz");
        let disposition = service.start(&command, &self.health_client, &health_url)?;
        Ok(PortStart {
            port,
            started: disposition.was_started(),
        })
    }
}

impl StartedLocalServices {
    pub fn backend_url(&self) -> String {
        self.state.backend_url()
    }

    pub fn dashboard_url(&self) -> String {
        self.state.dashboard_url()
    }
}

impl LocalDeploymentStatus {
    pub fn backend_label(&self) -> String {
        status_with_url(&self.backend, self.backend_url.as_deref())
    }

    pub fn dashboard_label(&self) -> String {
        status_with_url(&self.dashboard, self.dashboard_url.as_deref())
    }

    pub const fn is_ready(&self) -> bool {
        self.backend.is_running() && self.dashboard.is_running()
    }
}

struct PortStart {
    port: u16,
    started: bool,
}

fn available_port(preferred: Option<u16>, excluded: Option<u16>) -> Result<u16, CliError> {
    if let Some(port) = preferred
        && Some(port) != excluded
        && TcpListener::bind(socket_address(Ipv4Addr::LOCALHOST, port)).is_ok()
    {
        return Ok(port);
    }
    for _ in 0_u8..20 {
        let listener =
            TcpListener::bind(socket_address(Ipv4Addr::LOCALHOST, 0)).map_err(|source| {
                CliError::filesystem("allocate local deployment port", "127.0.0.1", source)
            })?;
        let port = listener
            .local_addr()
            .map_err(|source| {
                CliError::filesystem("inspect local deployment port", "127.0.0.1", source)
            })?
            .port();
        drop(listener);
        if Some(port) != excluded {
            return Ok(port);
        }
    }
    Err(CliError::InvalidConfiguration(
        "could not allocate distinct backend and dashboard ports".to_owned(),
    ))
}

const fn socket_address(host: Ipv4Addr, port: u16) -> SocketAddrV4 {
    SocketAddrV4::new(host, port)
}

fn status_with_url(status: &ServiceStatus, url: Option<&str>) -> String {
    let label = status.label();
    url.map_or_else(|| label.clone(), |url| format!("{label}, {url}"))
}

fn validate_state_root(path: &std::path::Path) -> Result<(), CliError> {
    if !path.is_absolute() {
        return Err(CliError::InvalidConfiguration(format!(
            "ABYSS_HOME must resolve to an absolute path: {}",
            path.display()
        )));
    }
    let value = path.to_str().ok_or_else(|| {
        CliError::InvalidConfiguration("ABYSS_HOME must be valid UTF-8".to_owned())
    })?;
    if value.contains(['\r', '\n']) {
        return Err(CliError::InvalidConfiguration(
            "ABYSS_HOME must not contain newlines".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, path::Path};

    use super::{available_port, validate_state_root};

    #[test]
    fn port_allocator_preserves_available_port_and_replaces_conflict() {
        let preferred = available_port(None, None).expect("first port should allocate");
        assert_eq!(
            available_port(Some(preferred), None).expect("available port should be preserved"),
            preferred
        );
        let blocker = TcpListener::bind(("127.0.0.1", preferred))
            .expect("preferred port should be available for blocker");
        let replacement =
            available_port(Some(preferred), None).expect("occupied port should be replaced");
        assert_ne!(replacement, preferred);
        drop(blocker);
    }

    #[test]
    fn state_root_must_be_absolute_and_single_line() {
        assert!(validate_state_root(Path::new("relative")).is_err());
        assert!(validate_state_root(Path::new("/tmp/abyss\nother")).is_err());
        assert!(validate_state_root(Path::new("/tmp/abyss")).is_ok());
    }
}
