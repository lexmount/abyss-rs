#![expect(
    clippy::multiple_crate_versions,
    reason = "reqwest/rustls currently pull transitive versions that cannot be unified in this workspace."
)]

//! Shared terminal SSO client flow for Abyss command-line tools.
//!
//! This crate owns the backend `/auth/terminal/*` contract, PKCE material,
//! polling loop, and local credential-file implementation. CLI binaries stay
//! responsible for argument parsing and user-facing output.

pub mod client;
pub mod credentials;
pub mod error;
pub mod pkce;
pub mod polling;
pub mod session;

pub use client::{
    ControlPlaneAuthClient, LogoutResponse, MeResponse, ReqwestControlPlaneAuthClient,
    TerminalExchangeRequest, TerminalExchangeResponse, TerminalPollRequest, TerminalPollResponse,
    TerminalStartRequest, TerminalStartResponse,
};
pub use credentials::{CredentialFile, CredentialStore, FileCredentialStore};
pub use error::TerminalAuthError;
pub use pkce::TerminalLoginMaterial;
pub use polling::{TerminalLoginAttempt, TerminalLoginOptions};
pub use session::{AuthenticatedUser, NativeSessionCredential};
