//! Runtime authentication state owned exclusively by the delivery worker.

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    AuthenticationConfig, DeliveryAuthentication, DeliveryPluginConfig, DeliveryPluginError,
};

/// Configured authentication mechanism exposed in product-facing status.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeliveryAuthenticationMode {
    /// No remote credential is required.
    None,
    /// A static complete Authorization header is loaded at startup.
    AuthorizationHeaderFile,
    /// A static complete Cookie header is loaded at startup.
    CookieHeaderFile,
    /// A product updates an opaque bearer credential through the control API.
    ManagedBearer,
}

/// Non-secret state of the configured authentication mechanism.
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeliveryAuthenticationState {
    /// The configured destination does not require a credential.
    NotRequired,
    /// A usable credential is active.
    Configured,
    /// Managed mode has not received a credential since worker startup.
    Missing,
    /// The destination rejected the active managed credential.
    AuthRequired,
}

/// Hot-swappable authentication shared by upload and product control requests.
pub struct DeliveryAuthenticationManager {
    mode: DeliveryAuthenticationMode,
    endpoint_origin: String,
    runtime: RwLock<AuthenticationRuntime>,
}

struct AuthenticationRuntime {
    authentication: DeliveryAuthentication,
    state: DeliveryAuthenticationState,
}

impl DeliveryAuthenticationManager {
    /// Loads static authentication or initializes empty product-managed state.
    ///
    /// # Errors
    ///
    /// Returns an error when the delivery endpoint is invalid or a configured
    /// static credential cannot be read.
    pub async fn load(config: &DeliveryPluginConfig) -> Result<Self, DeliveryPluginError> {
        let endpoint_origin = Self::http_origin(&config.delivery.endpoint)?;
        let (mode, runtime) = match &config.authentication {
            AuthenticationConfig::None => (
                DeliveryAuthenticationMode::None,
                AuthenticationRuntime {
                    authentication: DeliveryAuthentication::none(),
                    state: DeliveryAuthenticationState::NotRequired,
                },
            ),
            AuthenticationConfig::AuthorizationHeaderFile { .. } => (
                DeliveryAuthenticationMode::AuthorizationHeaderFile,
                AuthenticationRuntime {
                    authentication: config.load_authentication().await?,
                    state: DeliveryAuthenticationState::Configured,
                },
            ),
            AuthenticationConfig::CookieHeaderFile { .. } => (
                DeliveryAuthenticationMode::CookieHeaderFile,
                AuthenticationRuntime {
                    authentication: config.load_authentication().await?,
                    state: DeliveryAuthenticationState::Configured,
                },
            ),
            AuthenticationConfig::ManagedBearer => (
                DeliveryAuthenticationMode::ManagedBearer,
                AuthenticationRuntime {
                    authentication: DeliveryAuthentication::none(),
                    state: DeliveryAuthenticationState::Missing,
                },
            ),
        };
        Ok(Self {
            mode,
            endpoint_origin,
            runtime: RwLock::new(runtime),
        })
    }

    /// Returns the configured authentication mode.
    #[must_use]
    pub const fn mode(&self) -> &DeliveryAuthenticationMode {
        &self.mode
    }

    /// Returns current non-secret authentication state.
    pub async fn state(&self) -> DeliveryAuthenticationState {
        self.runtime.read().await.state.clone()
    }

    /// Snapshots authentication for one destination request.
    pub async fn for_request(&self) -> Option<DeliveryAuthentication> {
        let runtime = self.runtime.read().await;
        match (&self.mode, &runtime.state) {
            (
                DeliveryAuthenticationMode::ManagedBearer,
                DeliveryAuthenticationState::Configured,
            )
            | (
                DeliveryAuthenticationMode::None
                | DeliveryAuthenticationMode::AuthorizationHeaderFile
                | DeliveryAuthenticationMode::CookieHeaderFile,
                _,
            ) => Some(runtime.authentication.clone()),
            (DeliveryAuthenticationMode::ManagedBearer, _) => None,
        }
    }

    /// Activates one product-issued bearer token in the running worker.
    ///
    /// # Errors
    ///
    /// Returns an error when managed mode is disabled, input is invalid, or the
    /// audience differs from the destination.
    pub async fn set_managed_bearer(
        &self,
        bearer_token: &str,
        audience: &str,
    ) -> Result<(), DeliveryPluginError> {
        if !matches!(self.mode, DeliveryAuthenticationMode::ManagedBearer) {
            return Err(DeliveryPluginError::AuthenticationMutationUnsupported);
        }
        let bearer_token = bearer_token.trim();
        if bearer_token.is_empty() {
            return Err(DeliveryPluginError::InvalidCredentialUpdate(
                "bearer_token must not be empty".to_owned(),
            ));
        }
        let audience = Self::http_origin(audience)?;
        if audience != self.endpoint_origin {
            return Err(DeliveryPluginError::InvalidCredentialUpdate(format!(
                "credential audience {audience} does not match delivery endpoint origin {}",
                self.endpoint_origin
            )));
        }
        let mut runtime = self.runtime.write().await;
        runtime.authentication = DeliveryAuthentication::from_bearer(bearer_token);
        runtime.state = DeliveryAuthenticationState::Configured;
        drop(runtime);
        Ok(())
    }

    /// Clears in-memory managed authentication.
    ///
    /// # Errors
    ///
    /// Returns an error when managed mode is disabled.
    pub async fn clear_managed_bearer(&self) -> Result<(), DeliveryPluginError> {
        if !matches!(self.mode, DeliveryAuthenticationMode::ManagedBearer) {
            return Err(DeliveryPluginError::AuthenticationMutationUnsupported);
        }
        let mut runtime = self.runtime.write().await;
        runtime.authentication = DeliveryAuthentication::none();
        runtime.state = DeliveryAuthenticationState::Missing;
        drop(runtime);
        Ok(())
    }

    /// Invalidates a managed credential rejected with HTTP 401.
    pub async fn mark_unauthorized(&self) {
        if !matches!(self.mode, DeliveryAuthenticationMode::ManagedBearer) {
            return;
        }
        let mut runtime = self.runtime.write().await;
        runtime.authentication = DeliveryAuthentication::none();
        runtime.state = DeliveryAuthenticationState::AuthRequired;
    }

    fn http_origin(value: &str) -> Result<String, DeliveryPluginError> {
        let url = reqwest::Url::parse(value)
            .map_err(|error| DeliveryPluginError::InvalidDeliveryEndpoint(error.to_string()))?;
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(DeliveryPluginError::InvalidDeliveryEndpoint(
                "only http and https URLs are supported".to_owned(),
            ));
        }
        let origin = url.origin().ascii_serialization();
        if origin == "null" {
            return Err(DeliveryPluginError::InvalidDeliveryEndpoint(
                "URL does not have a network origin".to_owned(),
            ));
        }
        Ok(origin)
    }
}

#[cfg(test)]
mod tests {
    use crate::{AuthenticationConfig, DeliveryPluginConfig};

    use super::{DeliveryAuthenticationManager, DeliveryAuthenticationState};

    #[tokio::test]
    async fn managed_bearer_is_hot_swapped_and_cleared() {
        let mut config = DeliveryPluginConfig::default();
        config.delivery.endpoint = "https://example.test/v1/events".to_owned();
        config.authentication = AuthenticationConfig::ManagedBearer;
        let manager = DeliveryAuthenticationManager::load(&config)
            .await
            .expect("managed authentication should load");
        assert!(matches!(
            manager.state().await,
            DeliveryAuthenticationState::Missing
        ));

        manager
            .set_managed_bearer("native-token", "https://example.test/login")
            .await
            .expect("managed credential should update");
        assert_eq!(
            manager
                .for_request()
                .await
                .expect("credential should be active")
                .authorization_header(),
            Some("Bearer native-token")
        );

        manager
            .clear_managed_bearer()
            .await
            .expect("managed credential should clear");
        assert!(manager.for_request().await.is_none());
    }

    #[tokio::test]
    async fn rejects_bearer_for_a_different_origin() {
        let mut config = DeliveryPluginConfig::default();
        config.delivery.endpoint = "https://first.example/v1/events".to_owned();
        config.authentication = AuthenticationConfig::ManagedBearer;
        let manager = DeliveryAuthenticationManager::load(&config)
            .await
            .expect("managed authentication should load");

        let error = manager
            .set_managed_bearer("native-token", "https://second.example")
            .await
            .expect_err("cross-origin credential should be rejected");
        assert!(error.to_string().contains("does not match"));
        assert!(manager.for_request().await.is_none());
    }
}
