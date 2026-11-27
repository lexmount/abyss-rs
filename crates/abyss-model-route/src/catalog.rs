//! Employee configuration and the secret-free projection returned to the native UI.

mod discovery;
pub use discovery::{ListedModel, ModelListRequest};

use std::collections::{BTreeMap, BTreeSet};

use abyss_sdk::plugin::{AuthTokenScheme, ProxySettings};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize, Default)]
pub struct Catalog {
    harness_providers: BTreeMap<String, Box<[String]>>,
    providers: BTreeMap<String, Provider>,
}

#[derive(Clone, Deserialize, Serialize)]
struct Provider {
    base_url: Option<String>,
    credentials: BTreeMap<String, AssignedCredential>,
    #[serde(default, skip_serializing_if = "<[String]>::is_empty")]
    models: Box<[String]>,
}

#[derive(Deserialize, Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum CredentialKind {
    ApiKey,
    Account,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ServiceCredential {
    ApiKey { api_key: String },
    Account { login: String, secret: String },
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(untagged)]
enum Credential {
    // Earlier local files and saved profiles supplied the complete HTTP headers.
    ExplicitHeaders {
        kind: CredentialKind,
        headers: BTreeMap<String, String>,
    },
    Service(ServiceCredential),
}

#[derive(Clone, Deserialize, Serialize)]
struct AssignedCredential {
    #[serde(flatten)]
    value: Credential,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    proxy: Option<ProxySettings>,
}

impl Credential {
    const fn kind(&self) -> CredentialKind {
        match self {
            Self::ExplicitHeaders { kind, .. } => *kind,
            Self::Service(ServiceCredential::ApiKey { .. }) => CredentialKind::ApiKey,
            Self::Service(ServiceCredential::Account { .. }) => CredentialKind::Account,
        }
    }

    fn authentication(&self, provider_id: &str) -> Option<&str> {
        match self {
            Self::Service(ServiceCredential::ApiKey { api_key }) if !api_key.trim().is_empty() => {
                Some(api_key)
            }
            Self::Service(ServiceCredential::Account { login, secret })
                if provider_id == "anthropic"
                    && !login.trim().is_empty()
                    && secret
                        .strip_prefix("sk-ant-oat01-")
                        .is_some_and(|token| !token.is_empty())
                    && (1..=8192).contains(&secret.len())
                    && secret.bytes().all(|b| b.is_ascii_graphic()) =>
            {
                Some(secret)
            }
            Self::ExplicitHeaders { headers, .. } if headers.len() == 1 => {
                let (name, value) = headers.first_key_value()?;
                if name.eq_ignore_ascii_case("authorization") {
                    let (scheme, token) = value.split_once(' ')?;
                    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
                } else if (name.eq_ignore_ascii_case("x-api-key")
                    || name.eq_ignore_ascii_case("anthropic-api-key"))
                    && !value.is_empty()
                {
                    Some(value)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct CredentialInfo {
    kind: CredentialKind,
    configured: bool,
}

/// Project provider metadata once even when several harnesses share a provider.
#[derive(Serialize)]
pub struct Choices<'a> {
    harness_providers: BTreeMap<&'a str, Box<[&'a str]>>,
    providers: BTreeMap<&'a str, ProviderInfo<'a>>,
}

#[derive(Serialize)]
struct ProviderInfo<'a> {
    base_url: &'a str,
    credentials: BTreeMap<&'a str, CredentialInfo>,
    models: &'a [String],
}

fn identifier(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.starts_with(|c: char| c.is_ascii_lowercase())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn valid_model_id(id: &str) -> bool {
    !id.trim().is_empty() && id.len() <= 256 && !id.chars().any(char::is_control)
}

impl Provider {
    fn describe(&self, provider_id: &str) -> Result<Option<ProviderInfo<'_>>, &'static str> {
        let Some(base_url) = self.endpoint(provider_id)? else {
            return Ok(None);
        };
        if self.models.iter().any(|m| !valid_model_id(m)) {
            return Err("Invalid provider model name.");
        }
        let credentials = self
            .credentials
            .iter()
            .map(|(id, value)| {
                if !identifier(id) {
                    return Err("Invalid credential ID.");
                }
                if let Some(proxy) = &value.proxy {
                    proxy.validate()?;
                }
                Ok((
                    id.as_str(),
                    CredentialInfo {
                        kind: value.value.kind(),
                        configured: value.value.authentication(provider_id).is_some(),
                    },
                ))
            })
            .collect::<Result<_, _>>()?;
        Ok(Some(ProviderInfo {
            base_url,
            credentials,
            models: &self.models,
        }))
    }

    fn endpoint(&self, id: &str) -> Result<Option<&str>, &'static str> {
        let endpoint = self.base_url.as_deref().or(match id {
            "openai" => Some("https://api.openai.com/v1"),
            "anthropic" => Some("https://api.anthropic.com/v1"),
            "deepseek" => Some("https://api.deepseek.com/v1"),
            _ => None,
        });
        if let Some(url) = endpoint {
            https_url(url)?;
        }
        Ok(endpoint)
    }
}

impl Catalog {
    pub fn choices(&self) -> Result<Choices<'_>, &'static str> {
        let mut providers = BTreeMap::new();
        let mut harness_providers = BTreeMap::new();
        for (harness, ids) in &self.harness_providers {
            if !identifier(harness) {
                return Err("Invalid harness ID.");
            }
            let mut seen = BTreeSet::new();
            let mut available = Vec::new();
            for id in ids {
                if !identifier(id) || !seen.insert(id) {
                    return Err("Invalid harness provider assignment.");
                }
                if let Some(provider) = self.providers.get(id).filter(|p| !p.credentials.is_empty())
                {
                    if let std::collections::btree_map::Entry::Vacant(entry) =
                        providers.entry(id.as_str())
                    {
                        let Some(info) = provider.describe(id)? else {
                            continue;
                        };
                        entry.insert(info);
                    }
                    available.push(id.as_str());
                }
            }
            harness_providers.insert(harness.as_str(), available.into_boxed_slice());
        }
        Ok(Choices {
            harness_providers,
            providers,
        })
    }
}

/// Stable public IDs are the only selection data sent by the dashboard.
#[derive(Serialize, Deserialize, Clone)]
pub struct Selection {
    pub provider: String,
    pub credential: String,
    pub model: String,
}

pub struct SelectedRoute<'a> {
    pub base_url: &'a str,
    pub authentication: &'a str,
    pub auth_scheme: AuthTokenScheme,
    pub proxy: Option<&'a ProxySettings>,
    pub model: &'a str,
}

impl Catalog {
    fn provider_credential(
        &self,
        provider_id: &str,
        credential_id: &str,
    ) -> Result<(&Provider, &AssignedCredential), &'static str> {
        let provider = self
            .providers
            .get(provider_id)
            .ok_or("Provider unavailable.")?;
        let credential = provider
            .credentials
            .get(credential_id)
            .ok_or("Credential unavailable.")?;
        Ok((provider, credential))
    }

    pub fn resolve<'a>(
        &'a self,
        harness: &str,
        selection: &'a Selection,
    ) -> Result<SelectedRoute<'a>, &'static str> {
        if !self
            .harness_providers
            .get(harness)
            .is_some_and(|ids| ids.contains(&selection.provider))
        {
            return Err("Provider is unavailable for this harness.");
        }
        let (provider, credential) =
            self.provider_credential(&selection.provider, &selection.credential)?;
        let authentication = credential
            .value
            .authentication(&selection.provider)
            .ok_or("This credential cannot authenticate model requests.")?;
        if selection.model.trim().is_empty() {
            return Err("Enter a model name.");
        }
        Ok(SelectedRoute {
            base_url: provider
                .endpoint(&selection.provider)?
                .ok_or("Provider endpoint unavailable.")?,
            authentication,
            auth_scheme: match credential.value {
                Credential::Service(ServiceCredential::Account { .. }) => AuthTokenScheme::Bearer,
                _ => AuthTokenScheme::Existing,
            },
            proxy: credential.proxy.as_ref(),
            model: &selection.model,
        })
    }
}

pub fn https_url(value: &str) -> Result<reqwest::Url, &'static str> {
    let url = reqwest::Url::parse(value).map_err(|_| "Invalid HTTPS URL.")?;
    if url.scheme() != "https"
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '\\')
    {
        return Err("Expected an HTTPS URL without credentials, query or fragment.");
    }
    Ok(url)
}
