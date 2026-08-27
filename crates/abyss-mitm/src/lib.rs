#![expect(
    clippy::multiple_crate_versions,
    reason = "rustls/aws-lc TLS dependencies currently pull transitive untrusted/windows-sys versions that cannot be unified from this crate."
)]

//! MITM primitives shared by endpoint brokers.
//!
//! The crate owns product-level proxy behavior: explicit HTTP proxy request
//! normalization, flow classification, TLS termination with externally supplied
//! CA material, and HTTP/1 request decoding. Platform adapters provide duplex
//! byte IO plus normalized target metadata.

pub mod ca;

mod explicit_http;
mod http1;
#[cfg(windows)]
mod sys;
mod tls;
mod transparent;

pub use ca::{
    CaError, CaMaterialPersistence, CaMaterialState, CaResult, CaStatus, CaStore,
    CertificateAuthority, CertificateFingerprint, TrustStoreScope, TrustStoreStatus,
};
pub use explicit_http::{
    DEFAULT_EXPLICIT_PROXY_HEADER_TIMEOUT, DecodedExplicitRequest, ExplicitProxyErrorCategory,
    ExplicitProxyProtocol, ExplicitRequestDecoder, ExplicitRequestError,
    MAX_EXPLICIT_PROXY_HEADER_BYTES, TargetAuthority, TargetHost,
};
pub use http1::{Http1Error, MAX_HTTP1_HEADER_BYTES};
pub use tls::{TlsMitmError, install_default_crypto_provider};
pub use transparent::{
    AcceptedTcpFlow, BoxedDuplexStream, CapturedBody, CapturedBodyPlaintextDisplay, DuplexStream,
    FlowContext, FlowId, FlowIngress, FlowOperation, HookError, HookFuture, HookResult,
    HttpExchange, HttpHeadersDisplay, HttpRequestHeadDisplay, HttpResponseHeadDisplay,
    InterceptedHttpOutcome, MitmEngine, MitmHook, MitmTimeouts, OriginalDestination, SourceProcess,
    TlsDecryptionAction, TlsDecryptionContext, TlsDecryptionDecision, TlsDecryptionPolicy,
    TlsDecryptionPolicyError, TlsDecryptionRule, TlsErrorSide, TrafficDirection, TrafficObserver,
    TransparentFlowError, TransparentFlowOutcome, TransparentFlowSource,
    TransparentPassthroughOutcome, TransparentPassthroughProtocol, TransparentProtocol,
    ValidatedTlsDecryptionPolicy, WebSocketDirection, WebSocketMessage,
};
