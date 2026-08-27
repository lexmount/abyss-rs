//! Transparent MITM engine entrypoint.
//!
//! `MitmEngine` owns shared TLS configuration and dispatches each accepted flow
//! to the plain HTTP or HTTPS pipeline after lightweight protocol detection.

use crate::{
    CertificateAuthority,
    tls::{self as crate_tls, MitmTlsAuthority},
};
use arc_swap::ArcSwap;
use std::{sync::Arc, time::Duration};
use tokio_rustls::rustls;

use super::{
    AcceptedTcpFlow, MitmHook, TlsDecryptionPolicy, TlsDecryptionPolicyError, TransparentFlowError,
    TransparentFlowOutcome, ValidatedTlsDecryptionPolicy, hook::HookDispatcher,
    plain_http::PlainHttpFlow, protocol::DetectedProtocol, tls::TlsFlow,
};

/// Default maximum HTTP/1 body bytes captured for one request or response.
pub const DEFAULT_MAX_HTTP1_BODY_BYTES: usize = 0x0100_0000;

/// MITM engine shared by transparent proxy workers.
#[derive(Debug)]
pub struct MitmEngine {
    pub(super) tls_authority: MitmTlsAuthority,
    pub(super) upstream_tls_config: Arc<rustls::ClientConfig>,
    /// Observer dispatcher shared by all flows handled by this engine.
    ///
    /// Platform wrappers and brokers inject hooks here; the engine only carries
    /// them into the HTTP relay layer where complete exchanges are available.
    pub(super) hooks: HookDispatcher,
    /// Timeout budget for externally controlled transparent flow operations.
    pub timeouts: MitmTimeouts,
    /// Maximum decoded HTTP/1 body bytes captured per message.
    pub max_http1_body_bytes: usize,
    /// Domain-based decision for whether TLS flows should be decrypted.
    pub(super) tls_decryption_policy: ArcSwap<TlsDecryptionPolicy>,
}

/// Timeout budgets used by transparent MITM flow processing.
#[derive(Debug, Clone)]
pub struct MitmTimeouts {
    /// Maximum time to wait for enough bytes to classify the accepted flow.
    pub protocol_detection: Duration,
    /// Maximum time to wait for the first HTTP/1 request head.
    pub http1_request_head: Duration,
    /// Maximum time to complete client-side TLS termination.
    pub client_tls_handshake: Duration,
    /// Maximum time to wait for the first HTTP/1 response head.
    pub http1_response_head: Duration,
    /// Maximum time to wait while opening the original upstream TCP endpoint.
    pub upstream_connect: Duration,
    /// Maximum time to wait while completing upstream TLS.
    pub upstream_tls_handshake: Duration,
}

impl Default for MitmTimeouts {
    fn default() -> Self {
        Self {
            protocol_detection: Duration::from_secs(5),
            http1_request_head: Duration::from_secs(10),
            client_tls_handshake: Duration::from_secs(10),
            http1_response_head: Duration::from_mins(2),
            upstream_connect: Duration::from_secs(10),
            upstream_tls_handshake: Duration::from_secs(10),
        }
    }
}

impl MitmEngine {
    /// Builds a MITM engine from externally supplied root CA material.
    ///
    /// # Errors
    ///
    /// Returns an error when the CA cannot be parsed as a TLS signing issuer.
    pub fn from_ca(ca: &CertificateAuthority) -> Result<Self, TransparentFlowError> {
        Ok(Self {
            tls_authority: MitmTlsAuthority::from_ca(ca)
                .map_err(TransparentFlowError::TlsConfiguration)?,
            upstream_tls_config: crate_tls::webpki_upstream_client_config(),
            hooks: HookDispatcher::default(),
            timeouts: MitmTimeouts::default(),
            max_http1_body_bytes: DEFAULT_MAX_HTTP1_BODY_BYTES,
            tls_decryption_policy: ArcSwap::from_pointee(TlsDecryptionPolicy::default()),
        })
    }

    /// Adds a caller-provided hook implementation to the MITM engine.
    ///
    /// Hook implementations live outside this crate. This keeps `abyss-mitm`
    /// focused on transparent HTTP/TLS processing while still exposing decoded
    /// exchanges to audit or policy layers.
    #[must_use]
    pub fn with_hook<H>(self, hook: H) -> Self
    where
        H: MitmHook + 'static,
    {
        self.hooks.push(hook);
        self
    }

    /// Sets the maximum decoded HTTP/1 body bytes captured per message.
    #[must_use]
    pub const fn with_max_http1_body_bytes(mut self, limit: usize) -> Self {
        self.max_http1_body_bytes = limit;
        self
    }

    /// Sets the TLS decryption policy used before client TLS is accepted.
    ///
    /// # Errors
    ///
    /// Returns an error when rule ids or host patterns are invalid.
    pub fn with_tls_decryption_policy(
        mut self,
        policy: TlsDecryptionPolicy,
    ) -> Result<Self, TransparentFlowError> {
        policy.validate()?;
        self.tls_decryption_policy = ArcSwap::from_pointee(policy);
        Ok(self)
    }

    /// Returns the current TLS decryption policy snapshot.
    #[must_use]
    pub fn tls_decryption_policy(&self) -> Arc<TlsDecryptionPolicy> {
        self.tls_decryption_policy.load_full()
    }

    /// Atomically replaces the TLS decryption policy used by future TLS flows.
    ///
    /// Existing flows keep the policy snapshot they already loaded. This keeps
    /// REST-driven configuration changes from introducing per-flow locking or
    /// mid-stream policy changes.
    ///
    /// # Errors
    ///
    /// Returns an error when rule ids or host patterns are invalid.
    pub fn update_tls_decryption_policy(
        &self,
        policy: TlsDecryptionPolicy,
    ) -> Result<(), TlsDecryptionPolicyError> {
        let policy = ValidatedTlsDecryptionPolicy::new(policy)?;
        self.replace_tls_decryption_policy(policy);
        Ok(())
    }

    /// Atomically publishes a policy that was validated before an external
    /// durable commit.
    ///
    /// Existing flows keep their current snapshot. This operation is
    /// infallible so callers can persist policy state first without creating a
    /// post-commit error path or exposing a policy that persistence rejected.
    pub fn replace_tls_decryption_policy(&self, policy: ValidatedTlsDecryptionPolicy) {
        self.tls_decryption_policy
            .store(Arc::new(policy.into_inner()));
    }

    /// Handles one accepted transparent TCP flow.
    ///
    /// # Errors
    ///
    /// Returns an error when protocol detection, TLS handshaking, HTTP parsing,
    /// upstream connection, or byte relay fails.
    #[tracing::instrument(level = "trace", skip_all)]
    pub async fn handle_flow(
        &self,
        flow: AcceptedTcpFlow,
    ) -> Result<TransparentFlowOutcome, TransparentFlowError> {
        let detected = DetectedProtocol::detect(flow, self.timeouts.protocol_detection).await?;
        tracing::info!(
            peer_addr = ?detected.peer_addr(),
            local_addr = ?detected.local_addr(),
            original_destination = %detected.original_destination(),
            protocol = ?detected.protocol(),
            "MITM transparent flow protocol detected"
        );

        // Dispatch into the protocol-specific path. TLS performs one more
        // policy decision before it either enters HTTP MITM handling or raw
        // passthrough.
        let (protocol, flow) = detected.into_parts();
        match protocol {
            DetectedProtocol::PlainHttp => Box::pin(PlainHttpFlow::from(flow).handle(self)).await,
            DetectedProtocol::Tls => Box::pin(TlsFlow::from(flow).handle(self)).await,
        }
    }
}
