//! Explicit PKCE login and revocation using the shared terminal-auth contract.

use abyss_data_client::{ApiEndpoint, HttpTransport};
use abyss_terminal_auth::{
    NativeSessionCredential, TerminalLoginMaterial,
    client::{
        LogoutResponse, TerminalExchangeRequest, TerminalExchangeResponse, TerminalPollRequest,
        TerminalPollResponse, TerminalStartRequest, TerminalStartResponse,
    },
};
use serde_json::{Value, json};
use std::{
    io::{self, Write as _},
    time::{Duration, Instant},
};

use crate::{
    args::AuthCommand,
    config::{Authentication, ConfigFile, Profile},
    credentials::{CredentialResolver, CredentialVault},
    error::QueryError as Error,
};

pub struct AuthClient<'a> {
    profile: &'a Profile,
    endpoint: ApiEndpoint,
}
impl<'a> AuthClient<'a> {
    pub fn new(profile: &'a Profile) -> Result<Self, Error> {
        let Authentication::Terminal { endpoint, .. } = &profile.auth else {
            return Err(Error::Config(
                "login/logout requires a terminal-auth profile",
            ));
        };
        Ok(Self {
            profile,
            endpoint: ApiEndpoint::parse_with_http(endpoint, profile.allow_http)?,
        })
    }
    fn transport(&self, remaining: Duration) -> Result<HttpTransport, Error> {
        let options = self.profile.options()?;
        Ok(HttpTransport::new(
            options.timeout.min(remaining),
            options.max_response_bytes,
            options.ca_pem.as_deref(),
            0,
        )?)
    }
    fn url(&self, path: &str) -> Result<reqwest::Url, Error> {
        reqwest::Url::parse(&format!("{}{path}", self.endpoint.as_str()))
            .map_err(|_| Error::Config("invalid auth endpoint"))
    }
    pub fn login(&self, timeout: u64) -> Result<NativeSessionCredential, Error> {
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(timeout))
            .ok_or(Error::Config("invalid login timeout"))?;
        let material = TerminalLoginMaterial::generate();
        let start: TerminalStartResponse = self.transport(remaining(deadline)?)?.post(
            &self.url("auth/terminal/start")?,
            None,
            &TerminalStartRequest {
                state: material.state().into(),
                code_challenge: material.code_challenge().into(),
            },
        )?;
        validate_verification_url(&start.verification_url)?;
        writeln!(
            io::stderr().lock(),
            "{}",
            json!({"schema_version":1_u32,"login":{"verification_url":start.verification_url,"expires_at":start.expires_at}})
        )?;
        loop {
            if start.expires_at <= chrono::Utc::now() {
                return Err(Error::Auth("login attempt expired; run auth login again"));
            }
            let poll: TerminalPollResponse = self.transport(remaining(deadline)?)?.post(
                &self.url("auth/terminal/poll")?,
                None,
                &TerminalPollRequest {
                    attempt_id: start.attempt_id,
                    poll_token: start.poll_token.clone(),
                },
            )?;
            match poll {
                TerminalPollResponse::Pending => std::thread::sleep(
                    Duration::from_secs(start.poll_interval_seconds.max(1))
                        .min(remaining(deadline)?),
                ),
                TerminalPollResponse::Completed => {
                    let response: TerminalExchangeResponse =
                        self.transport(remaining(deadline)?)?.post(
                            &self.url("auth/terminal/exchange")?,
                            None,
                            &TerminalExchangeRequest {
                                attempt_id: start.attempt_id,
                                poll_token: start.poll_token,
                                state: material.state().into(),
                                code_verifier: material.code_verifier().into(),
                            },
                        )?;
                    return Ok(NativeSessionCredential {
                        token: response.token,
                        expires_at: response.expires_at,
                        user: response.user,
                    });
                }
                _ => return Err(Error::Protocol("unsupported terminal login state")),
            }
        }
    }
    pub fn logout(&self, token: &str) -> Result<(), Error> {
        let response: LogoutResponse =
            self.transport(Duration::from_secs(self.profile.timeout))?
                .post(&self.url("auth/native/logout")?, Some(token), &json!({}))?;
        if !response.ok {
            return Err(Error::Auth(
                "server did not confirm session revocation; local credential retained",
            ));
        }
        Ok(())
    }
}

pub fn execute(
    command: &AuthCommand,
    config: &ConfigFile,
    name: &str,
    profile: &Profile,
) -> Result<Value, Error> {
    match command {
        AuthCommand::Status => {
            if matches!(profile.auth, Authentication::None) {
                return Ok(json!({"mode":"none","credential_available":false}));
            }
            if let Authentication::Terminal { .. } = profile.auth {
                let credential = CredentialVault::new(config, name, profile)?.read()?;
                return Ok(
                    json!({"mode":"terminal","credential_available":true,"expires_at":credential.expires_at,"expired":credential.expires_at <= chrono::Utc::now()}),
                );
            }
            CredentialResolver::resolve(config, name, profile)?;
            Ok(json!({"mode":"bearer","credential_available":true}))
        }
        AuthCommand::Login { timeout } => {
            let vault = CredentialVault::new(config, name, profile)?;
            let session = AuthClient::new(profile)?.login(*timeout)?;
            let output =
                json!({"authenticated":true,"expires_at":session.expires_at,"user":session.user});
            vault.write(session)?;
            Ok(output)
        }
        AuthCommand::Logout { local_only } => {
            let vault = CredentialVault::new(config, name, profile)?;
            if !local_only {
                AuthClient::new(profile)?.logout(&vault.read()?.token)?;
            }
            vault.remove()?;
            Ok(json!({"credential_removed":true,"remote_revoked":!local_only}))
        }
    }
}
fn remaining(deadline: Instant) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|value| !value.is_zero())
        .ok_or(Error::Auth("terminal login timed out"))
}
fn validate_verification_url(value: &str) -> Result<(), Error> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| Error::Protocol("invalid login verification URL"))?;
    if !url.username().is_empty() || url.password().is_some() || value.chars().any(char::is_control)
    {
        return Err(Error::Protocol("unsafe login verification URL"));
    }
    // Permit query parameters needed by the browser flow, but require the same
    // transport policy as API roots. Never launch an untrusted URL as a process.
    let mut root = url;
    root.set_query(None);
    root.set_fragment(None);
    ApiEndpoint::parse(root.as_str())?;
    Ok(())
}
