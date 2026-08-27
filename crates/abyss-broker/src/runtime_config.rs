//! Dynamic MITM and Harness usage policy state.
//!
//! REST updates are kept in lock-free runtime snapshots and persisted to one
//! broker-owned policy file. This keeps dynamic policy durable across broker
//! restarts without mixing it into the static startup configuration file.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
};

use abyss_agent_hook::{HooksConfig, HooksRuntimeConfig};
use abyss_mitm::{TlsDecryptionPolicy, ValidatedTlsDecryptionPolicy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{fs, io::AsyncWriteExt as _, sync::Mutex};

use crate::error::BrokerError;

const RUNTIME_POLICY_SCHEMA_VERSION: u32 = 1;
const RUNTIME_POLICY_FILE_NAME: &str = "runtime-policy.toml";

/// REST representation of dynamic MITM behavior.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MitmConfig {
    /// TLS decryption policy evaluated for new flows.
    #[serde(default)]
    pub tls_decryption: TlsDecryptionPolicy,
}

/// Complete durable snapshot of REST-managed policy.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicies {
    /// Dynamic MITM policy.
    #[serde(default)]
    pub mitm: MitmConfig,
    /// Dynamic Harness usage policy.
    #[serde(default)]
    pub hooks: HooksConfig,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimePolicyFile {
    schema_version: u32,
    #[serde(default)]
    mitm: MitmConfig,
    #[serde(default)]
    hooks: HooksConfig,
}

/// Runtime policy loading or persistence failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RuntimePolicyError {
    /// An existing policy file could not be read.
    #[error("failed to read runtime policy `{path}`: {source}")]
    Read {
        /// Policy path that failed.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// Policy TOML could not be decoded.
    #[error("failed to parse runtime policy `{path}`: {source}")]
    Toml {
        /// Policy path that failed.
        path: PathBuf,
        /// Source TOML error.
        #[source]
        source: toml::de::Error,
    },
    /// Policy schema epoch is unsupported by this broker.
    #[error(
        "runtime policy `{path}` uses unsupported schema_version {actual}; expected {expected}"
    )]
    UnsupportedSchema {
        /// Policy path that failed.
        path: PathBuf,
        /// Version read from the file.
        actual: u32,
        /// Version supported by this broker.
        expected: u32,
    },
    /// MITM policy validation failed.
    #[error("invalid runtime MITM policy: {0}")]
    Mitm(#[from] abyss_mitm::TlsDecryptionPolicyError),
    /// A policy update could not be persisted.
    #[error("failed to {operation} runtime policy `{path}`: {source}")]
    Persist {
        /// Persistence operation that failed.
        operation: &'static str,
        /// File or directory involved in the failure.
        path: PathBuf,
        /// Source I/O error.
        #[source]
        source: io::Error,
    },
    /// A policy snapshot could not be serialized.
    #[error("failed to serialize runtime policy: {0}")]
    Serialize(#[from] toml::ser::Error),
}

/// Shared handle for reading and updating dynamic broker runtime settings.
#[derive(Clone)]
pub struct RuntimeConfigService {
    mitm: Arc<abyss_mitm::MitmEngine>,
    hooks: HooksRuntimeConfig,
    transaction: Arc<Mutex<RuntimePolicyTransaction>>,
}

/// Owns the committed snapshot and operations for serialized policy updates.
struct RuntimePolicyTransaction {
    current: RuntimePolicies,
    mitm: Arc<abyss_mitm::MitmEngine>,
    hooks: HooksRuntimeConfig,
    policy_path: PathBuf,
    #[cfg(test)]
    commit_pause: Option<Arc<TransactionCommitPause>>,
}

#[cfg(test)]
struct TransactionCommitPause {
    reached: tokio::sync::Notify,
    resume: tokio::sync::Notify,
}

impl RuntimePolicies {
    /// Loads the broker-owned policy snapshot, using safe defaults when absent.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing file cannot be parsed or validated.
    pub async fn load(path: &Path) -> Result<Self, RuntimePolicyError> {
        let contents = match fs::read_to_string(path).await {
            Ok(contents) => contents,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(source) => {
                return Err(RuntimePolicyError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let file = toml::from_str::<RuntimePolicyFile>(&contents).map_err(|source| {
            RuntimePolicyError::Toml {
                path: path.to_path_buf(),
                source,
            }
        })?;
        if file.schema_version != RUNTIME_POLICY_SCHEMA_VERSION {
            return Err(RuntimePolicyError::UnsupportedSchema {
                path: path.to_path_buf(),
                actual: file.schema_version,
                expected: RUNTIME_POLICY_SCHEMA_VERSION,
            });
        }
        let policies = Self {
            mitm: file.mitm,
            hooks: file.hooks,
        };
        policies.mitm.tls_decryption.validate()?;
        Ok(policies)
    }

    /// Returns the platform-local durable policy path.
    #[must_use]
    pub fn default_path(abyss_home: &Path) -> PathBuf {
        abyss_home.join(RUNTIME_POLICY_FILE_NAME)
    }
}

impl RuntimeConfigService {
    /// Creates a runtime config service backed by shared policy state.
    #[must_use]
    pub fn new(
        mitm: Arc<abyss_mitm::MitmEngine>,
        hooks: HooksRuntimeConfig,
        policy_path: PathBuf,
    ) -> Self {
        let transaction =
            RuntimePolicyTransaction::new(Arc::clone(&mitm), hooks.clone(), policy_path);
        Self {
            mitm,
            hooks,
            transaction: Arc::new(Mutex::new(transaction)),
        }
    }

    /// Returns the current broker MITM configuration.
    #[must_use]
    pub fn mitm_config(&self) -> MitmConfig {
        MitmConfig {
            tls_decryption: self.mitm.tls_decryption_policy().as_ref().clone(),
        }
    }

    /// Replaces and durably persists MITM policy for future flows.
    ///
    /// Existing flows keep the policy snapshot they already selected.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy is invalid or cannot be persisted.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn update_mitm_config(&self, config: MitmConfig) -> Result<MitmConfig, BrokerError> {
        // Keep lock acquisition request-scoped so cancelling a queued request
        // also cancels its update. Once acquired, move the transaction into an
        // owned task so request cancellation cannot interrupt a durable commit.
        let mut transaction = Arc::clone(&self.transaction).lock_owned().await;
        tokio::spawn(async move {
            let result = transaction.update_mitm(config).await;
            if let Err(error) = &result {
                tracing::error!(%error, "MITM runtime policy transaction failed");
            }
            result
        })
        .await
        .map_err(|source| BrokerError::task("update MITM runtime policy", source))?
    }

    /// Returns the current dynamic hook configuration.
    #[must_use]
    pub fn hooks_config(&self) -> HooksConfig {
        self.hooks.snapshot().as_ref().clone()
    }

    /// Replaces and durably persists hook policy for future invocations.
    ///
    /// # Errors
    ///
    /// Returns an error when the policy file cannot be persisted.
    pub async fn update_hooks_config(
        &self,
        config: HooksConfig,
    ) -> Result<HooksConfig, BrokerError> {
        // See `update_mitm_config`: waiting remains cancellable, while an
        // acquired write transaction always runs through its commit boundary.
        let mut transaction = Arc::clone(&self.transaction).lock_owned().await;
        tokio::spawn(async move {
            let result = transaction.update_hooks(config).await;
            if let Err(error) = &result {
                tracing::error!(%error, "hooks runtime policy transaction failed");
            }
            result
        })
        .await
        .map_err(|source| BrokerError::task("update hooks runtime policy", source))?
    }
}

impl RuntimePolicyTransaction {
    fn new(
        mitm: Arc<abyss_mitm::MitmEngine>,
        hooks: HooksRuntimeConfig,
        policy_path: PathBuf,
    ) -> Self {
        let current = RuntimePolicies {
            mitm: MitmConfig {
                tls_decryption: mitm.tls_decryption_policy().as_ref().clone(),
            },
            hooks: hooks.snapshot().as_ref().clone(),
        };
        Self {
            current,
            mitm,
            hooks,
            policy_path,
            #[cfg(test)]
            commit_pause: None,
        }
    }

    async fn update_mitm(&mut self, config: MitmConfig) -> Result<MitmConfig, BrokerError> {
        let validated_policy = ValidatedTlsDecryptionPolicy::new(config.tls_decryption.clone())
            .map_err(|source| BrokerError::invalid_config(source.to_string()))?;
        let candidate = RuntimePolicies {
            mitm: config,
            hooks: self.current.hooks.clone(),
        };
        self.persist(&candidate).await?;
        #[cfg(test)]
        self.pause_after_commit().await;
        self.mitm.replace_tls_decryption_policy(validated_policy);
        self.current = candidate;
        tracing::info!(
            default_action = ?self.current.mitm.tls_decryption.default_action,
            rule_count = self.current.mitm.tls_decryption.rules.len(),
            policy_path = %self.policy_path.display(),
            "broker MITM runtime config updated"
        );
        Ok(self.current.mitm.clone())
    }

    async fn update_hooks(&mut self, config: HooksConfig) -> Result<HooksConfig, BrokerError> {
        let candidate = RuntimePolicies {
            mitm: self.current.mitm.clone(),
            hooks: config,
        };
        self.persist(&candidate).await?;
        #[cfg(test)]
        self.pause_after_commit().await;
        let updated = self.hooks.update(candidate.hooks.clone());
        self.current = candidate;
        tracing::info!(
            harness_usage_enabled = updated.harness_usage.enabled,
            policy_path = %self.policy_path.display(),
            "broker hooks runtime config updated"
        );
        Ok(updated)
    }

    #[cfg(test)]
    async fn pause_after_commit(&mut self) {
        let Some(pause) = self.commit_pause.take() else {
            return;
        };
        pause.reached.notify_one();
        pause.resume.notified().await;
    }

    async fn persist(&self, policies: &RuntimePolicies) -> Result<(), RuntimePolicyError> {
        let file = RuntimePolicyFile {
            schema_version: RUNTIME_POLICY_SCHEMA_VERSION,
            mitm: policies.mitm.clone(),
            hooks: policies.hooks.clone(),
        };
        let mut contents = toml::to_string_pretty(&file)?;
        contents.push('\n');
        let parent = self.policy_path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent)
            .await
            .map_err(|source| RuntimePolicyError::Persist {
                operation: "create parent directory for",
                path: parent.to_path_buf(),
                source,
            })?;
        // macOS keeps broker state in a shared app-support directory that the
        // sandboxed host and Network Extension must traverse. The policy file
        // remains owner-only there; Linux broker homes can secure the parent.
        #[cfg(all(unix, not(target_os = "macos")))]
        self.secure_policy_directory(parent).await?;
        let file_name = self
            .policy_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(RUNTIME_POLICY_FILE_NAME);
        let temporary_path = parent.join(format!(
            ".{file_name}.{}-{}.tmp",
            std::process::id(),
            rand::random::<u64>()
        ));
        let result = self
            .write_and_replace(&temporary_path, contents.as_bytes())
            .await;
        if result.is_err() {
            drop(fs::remove_file(&temporary_path).await);
        }
        result
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    async fn secure_policy_directory(&self, directory: &Path) -> Result<(), RuntimePolicyError> {
        use std::os::unix::fs::PermissionsExt as _;

        fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))
            .await
            .map_err(|source| RuntimePolicyError::Persist {
                operation: "secure parent directory for",
                path: directory.to_path_buf(),
                source,
            })
    }

    async fn write_and_replace(
        &self,
        temporary_path: &Path,
        bytes: &[u8],
    ) -> Result<(), RuntimePolicyError> {
        #[cfg(unix)]
        let (parent, directory) = {
            let parent = self.policy_path.parent().unwrap_or_else(|| Path::new("."));
            let directory =
                fs::File::open(parent)
                    .await
                    .map_err(|source| RuntimePolicyError::Persist {
                        operation: "open parent directory for syncing",
                        path: parent.to_path_buf(),
                        source,
                    })?;
            (parent, directory)
        };
        let mut options = fs::OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file =
            options
                .open(temporary_path)
                .await
                .map_err(|source| RuntimePolicyError::Persist {
                    operation: "create temporary",
                    path: temporary_path.to_path_buf(),
                    source,
                })?;
        file.write_all(bytes)
            .await
            .map_err(|source| RuntimePolicyError::Persist {
                operation: "write temporary",
                path: temporary_path.to_path_buf(),
                source,
            })?;
        file.sync_all()
            .await
            .map_err(|source| RuntimePolicyError::Persist {
                operation: "sync temporary",
                path: temporary_path.to_path_buf(),
                source,
            })?;
        drop(file);

        #[cfg(unix)]
        directory
            .sync_all()
            .await
            .map_err(|source| RuntimePolicyError::Persist {
                operation: "sync temporary parent directory for",
                path: parent.to_path_buf(),
                source,
            })?;

        // Keeping the previous file until this call avoids a crash window
        // where no policy snapshot exists. Rust's cross-platform rename
        // implementation replaces an existing destination file.
        fs::rename(temporary_path, &self.policy_path)
            .await
            .map_err(|source| RuntimePolicyError::Persist {
                operation: "install",
                path: self.policy_path.clone(),
                source,
            })?;

        #[cfg(unix)]
        if let Err(source) = directory.sync_all().await {
            // The atomic rename above is the commit point: both the installed
            // file and subsequent in-memory publication must now use the new
            // policy. A directory-sync failure makes crash durability
            // uncertain, but treating the already-visible update as rejected
            // would split the broker's durable and live state.
            tracing::error!(
                error = %source,
                policy_path = %self.policy_path.display(),
                directory_path = %parent.display(),
                "runtime policy installed but rename durability could not be confirmed"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, Write as _},
        path::{Path, PathBuf},
        sync::Arc,
    };

    use abyss_agent_hook::{HooksConfig, HooksRuntimeConfig};
    use abyss_mitm::{CaMaterialPersistence, TlsDecryptionAction};
    use serde::Serialize;
    use tokio::sync::Barrier;

    use super::{MitmConfig, RuntimeConfigService, RuntimePolicies, TransactionCommitPause};

    struct TestCaMaterialPersistence;

    impl CaMaterialPersistence for TestCaMaterialPersistence {
        fn prepare_store(&self, directory: &Path, _private_key: &Path) -> io::Result<()> {
            fs::create_dir_all(directory)
        }

        fn write_public(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
            Self::write(path, contents)
        }

        fn write_private(&self, path: &Path, contents: &[u8]) -> io::Result<()> {
            Self::write(path, contents)
        }
    }

    impl TestCaMaterialPersistence {
        fn write(path: &Path, contents: &[u8]) -> io::Result<()> {
            let mut file = fs::File::create(path)?;
            file.write_all(contents)?;
            file.sync_all()
        }
    }

    #[test]
    fn default_policy_path_uses_the_current_schema_epoch() {
        assert_eq!(
            RuntimePolicies::default_path(Path::new("/var/lib/abyss")),
            PathBuf::from("/var/lib/abyss/runtime-policy.toml")
        );
    }

    #[tokio::test]
    async fn update_mitm_config_replaces_and_persists_runtime_policy() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let config = serde_json::from_value::<MitmConfig>(serde_json::json!({
            "tls_decryption": {
                "default_action": "passthrough",
                "missing_sni_action": "passthrough",
                "rules": [{
                    "id": "decrypt-openai",
                    "action": "intercept",
                    "destination_hosts": ["api.openai.com"]
                }]
            }
        }))
        .expect("MITM fixture should decode");

        let updated = service
            .update_mitm_config(config)
            .await
            .expect("valid MITM config should update");
        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("persisted policy should load");

        assert_eq!(
            updated.tls_decryption.default_action,
            TlsDecryptionAction::Passthrough
        );
        assert_eq!(persisted.mitm.tls_decryption.rules.len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            let mode = std::fs::metadata(&policy_path)
                .expect("persisted policy metadata should be readable")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
            #[cfg(not(target_os = "macos"))]
            {
                let parent_mode = std::fs::metadata(
                    policy_path
                        .parent()
                        .expect("test policy should have a parent directory"),
                )
                .expect("runtime policy directory metadata should be readable")
                .permissions()
                .mode()
                    & 0o777;
                assert_eq!(parent_mode, 0o700);
            }
        }
        cleanup(&policy_path).await;
    }

    #[tokio::test]
    async fn failed_mitm_persistence_does_not_publish_rejected_policy() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let previous = serde_json::from_value::<MitmConfig>(serde_json::json!({
            "tls_decryption": {
                "rules": [{
                    "id": "previous",
                    "action": "intercept",
                    "destination_hosts": ["api.anthropic.com"]
                }]
            }
        }))
        .expect("previous MITM fixture should decode");
        service
            .update_mitm_config(previous)
            .await
            .expect("previous MITM policy should update");
        tokio::fs::remove_file(&policy_path)
            .await
            .expect("persisted policy should be removable");
        tokio::fs::create_dir(&policy_path)
            .await
            .expect("directory at policy path should force persistence to fail");
        let config = serde_json::from_value::<MitmConfig>(serde_json::json!({
            "tls_decryption": {
                "rules": [{
                    "id": "replacement",
                    "action": "intercept",
                    "destination_hosts": ["api.openai.com"]
                }]
            }
        }))
        .expect("MITM fixture should decode");

        service
            .update_mitm_config(config)
            .await
            .expect_err("installing a policy over a directory should fail");

        let active = service.mitm_config();
        assert_eq!(active.tls_decryption.rules.len(), 1);
        assert_eq!(active.tls_decryption.rules[0].id, "previous");

        let committed = committed_policies(&service).await;
        assert_eq!(committed.mitm.tls_decryption.rules.len(), 1);
        assert_eq!(committed.mitm.tls_decryption.rules[0].id, "previous");

        tokio::fs::remove_dir(&policy_path)
            .await
            .expect("blocking directory should be removable");
        let mut hooks = HooksConfig::default();
        hooks.harness_usage.enabled = false;
        service
            .update_hooks_config(hooks)
            .await
            .expect("a later hooks policy should persist");
        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("later policy snapshot should load");
        assert_eq!(persisted.mitm.tls_decryption.rules.len(), 1);
        assert_eq!(persisted.mitm.tls_decryption.rules[0].id, "previous");
        cleanup(&policy_path).await;
    }

    #[tokio::test]
    async fn invalid_mitm_policy_does_not_create_policy_file() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let config = serde_json::from_value::<MitmConfig>(serde_json::json!({
            "tls_decryption": {
                "rules": [{
                    "id": "invalid",
                    "action": "intercept"
                }]
            }
        }))
        .expect("structurally valid fixture should decode");

        service
            .update_mitm_config(config)
            .await
            .expect_err("selector-free MITM rule should fail");

        assert!(!policy_path.exists());
    }

    #[tokio::test]
    async fn update_hooks_config_is_durable() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let mut config = HooksConfig::default();
        config.harness_usage.enabled = false;

        service
            .update_hooks_config(config)
            .await
            .expect("hook policy should persist");
        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("persisted policy should load");

        assert!(!persisted.hooks.harness_usage.enabled);
        assert!(!service.hooks_config().harness_usage.enabled);
        cleanup(&policy_path).await;
    }

    #[tokio::test]
    async fn failed_hooks_persistence_does_not_publish_rejected_policy() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let mut previous = HooksConfig::default();
        previous.harness_usage.enabled = false;
        service
            .update_hooks_config(previous)
            .await
            .expect("previous hooks policy should update");
        tokio::fs::remove_file(&policy_path)
            .await
            .expect("persisted policy should be removable");
        tokio::fs::create_dir(&policy_path)
            .await
            .expect("directory at policy path should force persistence to fail");

        service
            .update_hooks_config(HooksConfig::default())
            .await
            .expect_err("installing a policy over a directory should fail");

        assert!(!service.hooks_config().harness_usage.enabled);
        let committed = committed_policies(&service).await;
        assert!(!committed.hooks.harness_usage.enabled);

        tokio::fs::remove_dir(&policy_path)
            .await
            .expect("blocking directory should be removable");
        let mitm = mitm_config_with_rule("later-mitm", "api.openai.com");
        service
            .update_mitm_config(mitm)
            .await
            .expect("a later MITM policy should persist");
        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("later policy snapshot should load");
        assert!(!persisted.hooks.harness_usage.enabled);
        cleanup(&policy_path).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_mitm_and_hooks_updates_preserve_both_sections() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let mitm = mitm_config_with_rule("concurrent-mitm", "api.openai.com");
        let expected_mitm = mitm.clone();
        let mut hooks = HooksConfig::default();
        hooks.harness_usage.enabled = false;
        hooks.harness_usage.config.content.conversation_text = false;
        let expected_hooks = hooks.clone();
        let barrier = Arc::new(Barrier::new(3));

        let mitm_service = service.clone();
        let mitm_barrier = Arc::clone(&barrier);
        let mitm_update = tokio::spawn(async move {
            mitm_barrier.wait().await;
            mitm_service.update_mitm_config(mitm).await
        });
        let hooks_service = service.clone();
        let hooks_barrier = Arc::clone(&barrier);
        let hooks_update = tokio::spawn(async move {
            hooks_barrier.wait().await;
            hooks_service.update_hooks_config(hooks).await
        });
        barrier.wait().await;

        mitm_update
            .await
            .expect("MITM update task should finish")
            .expect("MITM update should succeed");
        hooks_update
            .await
            .expect("hooks update task should finish")
            .expect("hooks update should succeed");

        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("concurrent policy snapshot should load");
        assert_serialized_eq(&persisted.mitm, &expected_mitm);
        assert_serialized_eq(&persisted.hooks, &expected_hooks);
        assert_serialized_eq(&service.mitm_config(), &expected_mitm);
        assert_serialized_eq(&service.hooks_config(), &expected_hooks);
        let committed = committed_policies(&service).await;
        assert_serialized_eq(&committed.mitm, &expected_mitm);
        assert_serialized_eq(&committed.hooks, &expected_hooks);
        cleanup(&policy_path).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_update_waiter_does_not_cancel_committed_transaction() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let config = mitm_config_with_rule("cancelled-waiter", "api.openai.com");
        let expected = config.clone();
        let pause = Arc::new(TransactionCommitPause {
            reached: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
        });
        let mut transaction = service.transaction.lock().await;
        transaction.commit_pause = Some(Arc::clone(&pause));
        drop(transaction);

        let update_service = service.clone();
        let update_waiter =
            tokio::spawn(async move { update_service.update_mitm_config(config).await });
        tokio::time::timeout(std::time::Duration::from_secs(5), pause.reached.notified())
            .await
            .expect("transaction should reach its durable commit point");
        update_waiter.abort();
        let cancellation = update_waiter
            .await
            .expect_err("aborted request waiter should be cancelled");
        assert!(cancellation.is_cancelled());
        pause.resume.notify_one();

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let active = service.mitm_config();
                if active
                    .tls_decryption
                    .rules
                    .first()
                    .is_some_and(|rule| rule.id == "cancelled-waiter")
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached transaction should finish after its waiter is cancelled");

        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("committed policy snapshot should load");
        let committed = committed_policies(&service).await;
        assert_serialized_eq(&persisted.mitm, &expected);
        assert_serialized_eq(&committed.mitm, &expected);
        assert_serialized_eq(&service.mitm_config(), &expected);
        cleanup(&policy_path).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_queued_update_does_not_start_its_transaction() {
        let policy_path = temp_policy_path();
        let service = test_service(&policy_path);
        let transaction = service.transaction.lock().await;
        let queued_config = mitm_config_with_rule("cancelled-while-queued", "api.openai.com");
        let queued_service = service.clone();
        let queued_update =
            tokio::spawn(async move { queued_service.update_mitm_config(queued_config).await });

        tokio::task::yield_now().await;
        queued_update.abort();
        let cancellation = queued_update
            .await
            .expect_err("aborted queued update should be cancelled");
        assert!(cancellation.is_cancelled());
        drop(transaction);

        let replacement_hooks = HooksConfig::default();
        service
            .update_hooks_config(replacement_hooks)
            .await
            .expect("a later hooks transaction should complete");
        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("later policy snapshot should load");
        assert!(persisted.mitm.tls_decryption.rules.is_empty());
        assert!(service.mitm_config().tls_decryption.rules.is_empty());
        let committed = committed_policies(&service).await;
        assert!(committed.mitm.tls_decryption.rules.is_empty());
        cleanup(&policy_path).await;
    }

    #[tokio::test]
    async fn transaction_snapshot_starts_from_the_runtime_state() {
        let policy_path = temp_policy_path();
        let initial_mitm = mitm_config_with_rule("initial-mitm", "api.anthropic.com");
        let mitm = test_mitm_engine()
            .with_tls_decryption_policy(initial_mitm.tls_decryption.clone())
            .expect("initial MITM policy should be valid");
        let mut initial_hooks = HooksConfig::default();
        initial_hooks.harness_usage.enabled = false;
        let hooks = HooksRuntimeConfig::new(initial_hooks.clone());
        let service = RuntimeConfigService::new(Arc::new(mitm), hooks, policy_path.clone());

        let committed = committed_policies(&service).await;
        assert_serialized_eq(&committed.mitm, &initial_mitm);
        assert_serialized_eq(&committed.hooks, &initial_hooks);

        let replacement_hooks = HooksConfig::default();
        service
            .update_hooks_config(replacement_hooks)
            .await
            .expect("replacement hooks policy should persist");
        let persisted = RuntimePolicies::load(&policy_path)
            .await
            .expect("policy snapshot should load");
        assert_serialized_eq(&persisted.mitm, &initial_mitm);
        cleanup(&policy_path).await;
    }

    #[tokio::test]
    async fn missing_policy_file_uses_safe_defaults() {
        let policy_path = temp_policy_path();
        let policies = RuntimePolicies::load(&policy_path)
            .await
            .expect("missing policy should use defaults");

        assert_eq!(
            policies.mitm.tls_decryption.default_action,
            TlsDecryptionAction::Passthrough
        );
        assert!(policies.mitm.tls_decryption.rules.is_empty());
    }

    fn test_service(policy_path: &Path) -> RuntimeConfigService {
        RuntimeConfigService::new(
            Arc::new(test_mitm_engine()),
            HooksRuntimeConfig::default_enabled(),
            policy_path.to_path_buf(),
        )
    }

    fn mitm_config_with_rule(id: &str, destination_host: &str) -> MitmConfig {
        serde_json::from_value(serde_json::json!({
            "tls_decryption": {
                "rules": [{
                    "id": id,
                    "action": "intercept",
                    "destination_hosts": [destination_host]
                }]
            }
        }))
        .expect("MITM fixture should decode")
    }

    fn assert_serialized_eq<T>(actual: &T, expected: &T)
    where
        T: Serialize,
    {
        assert_eq!(
            serde_json::to_value(actual).expect("actual value should serialize"),
            serde_json::to_value(expected).expect("expected value should serialize")
        );
    }

    async fn committed_policies(service: &RuntimeConfigService) -> RuntimePolicies {
        service.transaction.lock().await.current.clone()
    }

    fn test_mitm_engine() -> abyss_mitm::MitmEngine {
        let ca_dir = std::env::temp_dir().join(format!(
            "abyss-broker-runtime-config-ca-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let ca = abyss_mitm::CaStore::at(&ca_dir)
            .load_or_generate_with(&TestCaMaterialPersistence)
            .expect("test CA should generate");
        let engine = abyss_mitm::MitmEngine::from_ca(&ca).expect("test MITM engine should build");
        drop(std::fs::remove_dir_all(ca_dir));
        engine
    }

    fn temp_policy_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!(
                "abyss-broker-runtime-policy-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ))
            .join("runtime-policy.toml")
    }

    async fn cleanup(path: &Path) {
        if let Some(parent) = path.parent() {
            drop(tokio::fs::remove_dir_all(parent).await);
        }
    }
}
