//! Terminal SSO start and polling orchestration.

use std::{
    thread,
    time::{Duration, Instant},
};

use crate::{
    client::{
        ControlPlaneAuthClient, TerminalExchangeRequest, TerminalPollRequest, TerminalPollResponse,
        TerminalStartRequest, TerminalStartResponse,
    },
    error::TerminalAuthError,
    pkce::TerminalLoginMaterial,
    session::NativeSessionCredential,
};

const MIN_POLL_INTERVAL_SECONDS: u64 = 1;

/// Timeout and interval configuration for terminal login polling.
#[derive(Clone)]
pub struct TerminalLoginOptions {
    /// Maximum time to wait for browser SSO completion.
    pub timeout_seconds: u64,
    /// Optional client override for the server-recommended polling interval.
    pub poll_interval_seconds: Option<u64>,
}

/// In-progress terminal login attempt and its local PKCE material.
pub struct TerminalLoginAttempt {
    start: TerminalStartResponse,
    material: TerminalLoginMaterial,
}

impl TerminalLoginOptions {
    /// Creates polling options with a required timeout.
    #[must_use]
    pub const fn new(timeout_seconds: u64) -> Self {
        Self {
            timeout_seconds,
            poll_interval_seconds: None,
        }
    }

    /// Sets or clears the client-side polling interval override.
    #[must_use]
    pub const fn with_poll_interval_seconds(mut self, poll_interval_seconds: Option<u64>) -> Self {
        self.poll_interval_seconds = poll_interval_seconds;
        self
    }
}

impl TerminalLoginAttempt {
    /// Starts a new terminal login attempt through the control plane.
    ///
    /// # Errors
    ///
    /// Returns an error when PKCE material cannot be accepted by the control
    /// plane or the start request fails.
    pub fn start<C>(client: &C) -> Result<Self, TerminalAuthError>
    where
        C: ControlPlaneAuthClient,
    {
        let material = TerminalLoginMaterial::generate();
        let start = client.start_terminal_login(&TerminalStartRequest {
            state: material.state().to_owned(),
            code_challenge: material.code_challenge().to_owned(),
        })?;
        Ok(Self { start, material })
    }

    /// Returns the browser URL the user must open to complete SSO.
    #[must_use]
    pub fn verification_url(&self) -> &str {
        &self.start.verification_url
    }

    /// Returns the polling interval recommended by the control plane.
    #[must_use]
    pub const fn server_poll_interval_seconds(&self) -> u64 {
        self.start.poll_interval_seconds
    }

    /// Polls until the attempt authenticates or the configured timeout expires.
    ///
    /// # Errors
    ///
    /// Returns an error when the timeout is invalid, polling fails, the
    /// control plane rejects the attempt, or the deadline expires.
    pub fn poll_until_authenticated<C>(
        &self,
        client: &C,
        options: &TerminalLoginOptions,
    ) -> Result<NativeSessionCredential, TerminalAuthError>
    where
        C: ControlPlaneAuthClient,
    {
        if options.timeout_seconds == 0 {
            return Err(TerminalAuthError::InvalidTimeout);
        }
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(options.timeout_seconds))
            .ok_or(TerminalAuthError::InvalidTimeout)?;
        let poll_interval = options
            .poll_interval_seconds
            .unwrap_or_else(|| self.server_poll_interval_seconds())
            .max(MIN_POLL_INTERVAL_SECONDS);
        loop {
            match self.poll_once(client)? {
                TerminalPollResponse::Pending => {
                    if Instant::now() >= deadline {
                        return Err(TerminalAuthError::TerminalLoginTimeout {
                            seconds: options.timeout_seconds,
                        });
                    }
                    thread::sleep(Duration::from_secs(poll_interval));
                }
                TerminalPollResponse::Completed => {
                    let response = self.exchange(client)?;
                    return Ok(NativeSessionCredential {
                        token: response.token,
                        expires_at: response.expires_at,
                        user: response.user,
                    });
                }
            }
        }
    }

    /// Polls the control plane once for this attempt.
    ///
    /// # Errors
    ///
    /// Returns an error when the control-plane polling request fails or returns
    /// an invalid response.
    pub fn poll_once<C>(&self, client: &C) -> Result<TerminalPollResponse, TerminalAuthError>
    where
        C: ControlPlaneAuthClient,
    {
        client.poll_terminal_login(&TerminalPollRequest {
            attempt_id: self.start.attempt_id,
            poll_token: self.start.poll_token.clone(),
        })
    }

    /// Exchanges a completed attempt for a native session.
    ///
    /// # Errors
    ///
    /// Returns an error when the control-plane exchange request fails or the
    /// attempt is not ready to consume.
    pub fn exchange<C>(
        &self,
        client: &C,
    ) -> Result<crate::client::TerminalExchangeResponse, TerminalAuthError>
    where
        C: ControlPlaneAuthClient,
    {
        client.exchange_terminal_login(&TerminalExchangeRequest {
            attempt_id: self.start.attempt_id,
            poll_token: self.start.poll_token.clone(),
            state: self.material.state().to_owned(),
            code_verifier: self.material.code_verifier().to_owned(),
        })
    }
}
