//! Endpoint CLI filesystem paths.

use std::path::PathBuf;

const BROKER_CONFIG_FILE_NAME: &str = "broker-config.toml";

/// Endpoint CLI state rooted at the active platform's selected directory.
#[derive(Debug, Clone)]
pub struct CliPaths {
    root: PathBuf,
}

impl CliPaths {
    /// Builds paths from the current platform environment.
    pub fn from_env() -> Result<Self, crate::error::CliError> {
        crate::platform::platform_adapter()
            .state_root()
            .map(|root| Self { root })
    }

    /// Creates paths rooted at a test or package directory.
    #[cfg(test)]
    pub(crate) const fn at(root: PathBuf) -> Self {
        Self { root }
    }

    /// Product-owned state root.
    #[must_use]
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// Terminal credential file below the platform-managed CLI state root.
    #[must_use]
    pub fn credential_file(&self) -> PathBuf {
        self.root.join("auth").join("credentials.json")
    }

    /// Broker control token file.
    #[must_use]
    pub fn broker_token_file(&self) -> PathBuf {
        self.root.join("runtime").join("broker.token")
    }

    /// Broker startup ownership record for CLI-managed user processes.
    #[must_use]
    pub fn broker_startup_info_file(&self) -> PathBuf {
        self.root.join("runtime").join("startup-info.json")
    }

    /// Per-user lock serializing CLI-managed broker lifecycle operations.
    #[must_use]
    pub fn broker_start_lock_file(&self) -> PathBuf {
        self.root.join("runtime").join("start.lock")
    }

    /// CLI-owned product configuration.
    #[must_use]
    pub fn product_config_file(&self) -> PathBuf {
        self.root.join("product-config.json")
    }

    /// Readiness identity published after the delivery worker handshake.
    #[must_use]
    pub fn delivery_worker_startup_info_file(&self) -> PathBuf {
        self.root
            .join("runtime")
            .join("delivery-worker-startup.json")
    }

    /// Per-process bearer token protecting the delivery worker control API.
    #[must_use]
    pub fn delivery_control_token_file(&self) -> PathBuf {
        self.root.join("runtime").join("delivery-control.token")
    }

    /// Lock serializing CLI delivery worker startup attempts.
    #[must_use]
    pub fn delivery_worker_start_lock_file(&self) -> PathBuf {
        self.root.join("runtime").join("delivery-worker-start.lock")
    }

    /// Process-lifetime lock inherited by the CLI delivery worker.
    #[must_use]
    pub fn delivery_worker_lifetime_lock_file(&self) -> PathBuf {
        self.root.join("runtime").join("delivery-worker.lock")
    }

    /// Persisted broker startup configuration.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.root.join(BROKER_CONFIG_FILE_NAME)
    }

    /// Persisted MITM and hook runtime policy.
    #[must_use]
    pub fn runtime_policy_file(&self) -> PathBuf {
        self.root.join("runtime-policy.toml")
    }

    /// Directory for support bundles and broker logs.
    #[must_use]
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// Root for the CLI-managed local backend and dashboard deployment.
    #[must_use]
    pub fn local_deployment_dir(&self) -> PathBuf {
        self.root.join("local")
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::CliPaths;

    #[test]
    fn paths_share_the_abyss_root() {
        let paths = CliPaths::at(PathBuf::from("/tmp/abyss"));

        assert_eq!(
            paths.credential_file(),
            PathBuf::from("/tmp/abyss/auth/credentials.json")
        );
        assert_eq!(
            paths.broker_token_file(),
            PathBuf::from("/tmp/abyss/runtime/broker.token")
        );
        assert_eq!(
            paths.broker_startup_info_file(),
            PathBuf::from("/tmp/abyss/runtime/startup-info.json")
        );
        assert_eq!(
            paths.broker_start_lock_file(),
            PathBuf::from("/tmp/abyss/runtime/start.lock")
        );
        assert_eq!(
            paths.product_config_file(),
            PathBuf::from("/tmp/abyss/product-config.json")
        );
        assert_eq!(
            paths.delivery_worker_startup_info_file(),
            PathBuf::from("/tmp/abyss/runtime/delivery-worker-startup.json")
        );
        assert_eq!(
            paths.delivery_control_token_file(),
            PathBuf::from("/tmp/abyss/runtime/delivery-control.token")
        );
        assert_eq!(
            paths.delivery_worker_start_lock_file(),
            PathBuf::from("/tmp/abyss/runtime/delivery-worker-start.lock")
        );
        assert_eq!(
            paths.delivery_worker_lifetime_lock_file(),
            PathBuf::from("/tmp/abyss/runtime/delivery-worker.lock")
        );
        assert_eq!(
            paths.config_file(),
            PathBuf::from("/tmp/abyss/broker-config.toml")
        );
        assert_eq!(
            paths.runtime_policy_file(),
            PathBuf::from("/tmp/abyss/runtime-policy.toml")
        );
        assert_eq!(paths.logs_dir(), PathBuf::from("/tmp/abyss/logs"));
        assert_eq!(
            paths.local_deployment_dir(),
            PathBuf::from("/tmp/abyss/local")
        );
    }
}
