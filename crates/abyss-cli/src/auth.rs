//! Endpoint terminal authentication owned by the CLI product.

use abyss_terminal_auth::{
    ControlPlaneAuthClient as _, CredentialFile, CredentialStore, ReqwestControlPlaneAuthClient,
    TerminalLoginAttempt, TerminalLoginOptions,
};

use crate::{
    cli::{LoginArgs, LogoutArgs},
    credential::CliCredentialStore,
    delivery::DeliveryWorker,
    error::CliError,
    paths::CliPaths,
    product_config::CliProductConfig,
};

/// Runs the endpoint CLI login and logout flows.
pub struct AuthCommandRunner;

impl AuthCommandRunner {
    /// Completes browser SSO and persists the CLI-owned credential.
    pub fn login(args: &LoginArgs) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        let product_config = CliProductConfig::load(&paths.product_config_file())?;
        let store = CliCredentialStore::from_paths(&paths)?;
        let control_plane = resolve_control_plane(
            args.control_plane.as_deref(),
            product_config.control_plane_url(),
        )?;
        let client = ReqwestControlPlaneAuthClient::new(&control_plane)?;
        let attempt = TerminalLoginAttempt::start(&client)?;

        println!("\nLogin\n");
        println!("Open this URL in a browser to sign in:");
        println!("{}", attempt.verification_url());
        println!("\nWaiting for login to complete...");
        let credential = attempt.poll_until_authenticated(
            &client,
            &TerminalLoginOptions::new(args.timeout_seconds)
                .with_poll_interval_seconds(args.poll_interval_seconds),
        )?;
        let email = credential.user.email.clone();
        let expires_at = credential.expires_at;
        store.write(&CredentialFile::from_session(control_plane, credential))?;
        if let Some(delivery) = DeliveryWorker::discover(&paths)? {
            let credential = store.read()?;
            delivery.set_bearer_if_managed(&credential.token, &credential.control_plane)?;
        }
        println!(
            "Login succeeded as {email} (expires_at={expires_at}). Credential stored at {}.",
            store.path().display()
        );
        Ok(())
    }

    /// Revokes the native credential and removes the local credential file.
    pub fn logout(args: &LogoutArgs) -> Result<(), CliError> {
        let paths = CliPaths::from_env()?;
        let store = CliCredentialStore::from_paths(&paths)?;
        let credential = store.read()?;
        let control_plane = args
            .control_plane
            .as_deref()
            .unwrap_or(&credential.control_plane);
        let client = ReqwestControlPlaneAuthClient::new(control_plane)?;
        if let Some(delivery) = DeliveryWorker::discover(&paths)? {
            delivery.clear_bearer_if_managed()?;
        }
        store.remove()?;
        if let Err(error) = client.native_logout(&credential.token) {
            eprintln!("Warning: local logout succeeded, but remote revocation failed: {error}");
        }
        println!("Logged out.");
        Ok(())
    }
}

/// Resolves the configured control-plane endpoint for the user-facing login.
pub fn resolve_control_plane(
    value: Option<&str>,
    configured: Option<&str>,
) -> Result<String, CliError> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .or_else(|| configured.map(str::to_owned))
        .ok_or_else(|| {
            CliError::InvalidConfiguration(
                "product.control_plane is required to run `abyss login` unless --control-plane is provided"
                    .to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::resolve_control_plane;

    #[test]
    fn explicit_control_plane_overrides_the_product_configuration() {
        assert_eq!(
            resolve_control_plane(
                Some("  https://override.example.test/api  "),
                Some("https://configured.example.test/api")
            )
            .expect("explicit control plane should resolve"),
            "https://override.example.test/api"
        );
    }

    #[test]
    fn missing_or_empty_override_uses_the_product_configuration() {
        for value in [None, Some(""), Some("  ")] {
            assert_eq!(
                resolve_control_plane(value, Some("https://configured.example.test/api"))
                    .expect("configured control plane should resolve"),
                "https://configured.example.test/api"
            );
        }
    }

    #[test]
    fn login_without_any_control_plane_is_rejected() {
        let error = resolve_control_plane(None, None)
            .expect_err("login should require an explicit or configured control plane");

        assert!(
            error
                .to_string()
                .contains("product.control_plane is required")
        );
    }
}
