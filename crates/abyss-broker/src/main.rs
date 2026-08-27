#![expect(
    clippy::multiple_crate_versions,
    reason = "abyss-broker embeds abyss-mitm; rustls/aws-lc TLS dependencies currently pull transitive versions that cannot be unified here."
)]

//! Cross-platform endpoint broker entrypoint.
//!
//! `abyss-broker` owns the local proxy listener that receives platform-specific
//! traffic redirection. Platform adapters such as the Windows WFP wrapper should
//! configure OS redirection toward this process instead of embedding proxy
//! runtime behavior themselves.

mod api;
mod auth;
mod cli;
mod config;
mod connection;
mod diagnostics;
mod error;
mod ingress;
mod logging;
mod network_diagnostics;
mod platform;
mod plugin;
mod process_context;
mod proxy;
mod runtime_config;
mod startup_info;
mod support_logs;
mod sys;
mod traffic;

use std::{process::ExitCode, sync::Arc};

use abyss_agent_hook::{
    AgentEventSink, HarnessUsageHook, HarnessUsageHookConfig, HooksRuntimeConfig,
};
use cli::Cli;
use config::BrokerConfig;
use error::BrokerError;
use platform::{PlatformAdapter, platform_adapter};
use plugin::PluginServer;
use runtime_config::RuntimePolicies;

struct BrokerRuntime {
    mitm: abyss_mitm::MitmEngine,
    hooks: HooksRuntimeConfig,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let platform = platform_adapter();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("abyss-broker: failed to initialize async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let broker_config =
        match runtime.block_on(BrokerConfig::load(cli.config.as_deref(), platform.as_ref())) {
            Ok(config) => config,
            Err(error) => {
                eprintln!("abyss-broker: {error}");
                return ExitCode::FAILURE;
            }
        };
    let _trace_guard = match logging::init(&broker_config.devtools, platform.as_ref()) {
        Ok(trace_guard) => trace_guard,
        Err(error) => {
            eprintln!("abyss-broker: failed to initialize logging: {error}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli, platform, broker_config)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("abyss-broker: {error}");
            ExitCode::FAILURE
        }
    }
}

#[tracing::instrument(level = "trace", skip_all)]
async fn run(
    cli: Cli,
    platform: Box<dyn PlatformAdapter>,
    broker_config: BrokerConfig,
) -> Result<(), BrokerError> {
    let ca_dir = broker_config.ca_path(platform.as_ref());
    let ca = tokio::task::spawn_blocking(move || abyss_mitm::CaStore::at(ca_dir).load_required())
        .await
        .map_err(|source| BrokerError::task("load broker MITM root CA", source))??;
    tracing::info!(
        fingerprint_sha256 = %ca.fingerprint_sha256(),
        "abyss-broker external MITM root CA loaded"
    );
    let proxy_plan = broker_config.proxy.plan()?;
    let abyss_home = platform.abyss_home();
    let plugin_server = PluginServer::bind(&abyss_home).await?;
    let plugin_event_sink = plugin_server.event_sink();
    let runtime_policy_path = RuntimePolicies::default_path(&abyss_home);
    let runtime_policies = RuntimePolicies::load(&runtime_policy_path).await?;
    let runtime = BrokerRuntime::from_policies(&ca, runtime_policies)?
        .with_harness_usage_hook(plugin_event_sink);
    let database_path = network_diagnostics::database_path(platform.as_ref());
    let network_observations = Arc::new(
        tokio::task::spawn_blocking(move || {
            network_diagnostics::NetworkObservationStore::open(database_path)
        })
        .await
        .map_err(|source| BrokerError::task("open network observation store", source))??,
    );

    let auth_token_file = cli
        .auth_token_file
        .unwrap_or_else(|| auth::default_auth_token_file(cli.api, platform.as_ref()));
    let auth_token = auth::AuthTokenFile::create(auth_token_file.clone()).await?;
    let bearer_token = auth_token.token().to_owned();
    auth_token
        .run_with_cleanup(async move {
            let broker_logs = support_logs::BrokerLogCollector::installed(
                &broker_config.devtools,
                platform.as_ref(),
            );
            api::serve(
                cli.api,
                proxy_plan,
                auth_token_file,
                cli.startup_info_file,
                bearer_token,
                api::RuntimeServices {
                    mitm: runtime.mitm,
                    hooks: runtime.hooks,
                    runtime_policy_path,
                    broker_logs,
                    network_observations,
                    plugin_server,
                },
            )
            .await
        })
        .await
}

impl BrokerRuntime {
    fn from_policies(
        ca: &abyss_mitm::CertificateAuthority,
        policies: RuntimePolicies,
    ) -> Result<Self, BrokerError> {
        tracing::info!(
            default_action = ?policies.mitm.tls_decryption.default_action,
            rule_count = policies.mitm.tls_decryption.rules.len(),
            "abyss-broker MITM runtime policy loaded"
        );
        let hooks = HooksRuntimeConfig::new(policies.hooks);
        let hooks_snapshot = hooks.snapshot();
        tracing::info!(
            harness_usage_enabled = hooks_snapshot.harness_usage.enabled,
            "abyss-broker hooks runtime policy loaded"
        );
        let mitm = abyss_mitm::MitmEngine::from_ca(ca)?
            .with_tls_decryption_policy(policies.mitm.tls_decryption)?;
        Ok(Self { mitm, hooks })
    }

    fn with_harness_usage_hook<S>(self, event_sink: S) -> Self
    where
        S: AgentEventSink + Clone + 'static,
    {
        let hook_config = HarnessUsageHookConfig::from_platform();
        tracing::info!(
            host_name = hook_config.device.hostname.as_deref().unwrap_or(""),
            "abyss-broker Agent event hooks enabled"
        );
        let mitm = self
            .mitm
            .with_hook(HarnessUsageHook::with_runtime_config_and_event_sink(
                hook_config,
                self.hooks.clone(),
                event_sink,
            ));
        Self {
            mitm,
            hooks: self.hooks,
        }
    }
}
