//! User-scoped catalog acquisition. Native login credentials are audience-bound.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};

use reqwest::{Url, blocking::Client, redirect::Policy};
use serde::Deserialize;

use crate::catalog::Catalog;

const MAX_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    File { path: PathBuf },
    Service { url: String, sso: bool },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeSession {
    origin: String,
    bearer: String,
}

pub fn https_url(value: &str) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "Invalid HTTPS URL.")?;
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

fn service_url(value: &str) -> Result<Url, &'static str> {
    let url = Url::parse(value).map_err(|_| "Invalid configuration service URL.")?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err("Expected an HTTP or HTTPS configuration service URL.");
    }
    Ok(url)
}

pub fn read_catalog<R: Read>(reader: R) -> Result<Catalog, &'static str> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read model catalog.")?;
    if bytes.len() > usize::try_from(MAX_BYTES).unwrap_or(usize::MAX) {
        return Err("Model catalog exceeds 2 MiB.");
    }
    // Parser diagnostics may quote input, including secrets.
    serde_json::from_slice(&bytes).map_err(|_| "Invalid model catalog.")
}

pub fn json_file_name(path: &Path) -> Result<&str, &'static str> {
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
    {
        return Err("Select a .json configuration file.");
    }
    path.to_str().ok_or("Invalid file name.")
}

fn local_catalog(path: &Path) -> Result<Catalog, &'static str> {
    if !path.is_absolute() {
        return Err("Select an absolute configuration path.");
    }
    json_file_name(path)?;
    if !path.is_file() {
        return Err("Configuration file is unavailable.");
    }
    read_catalog(File::open(path).map_err(|_| "Cannot open configuration file.")?)
}

impl Source {
    pub fn label(&self) -> Result<&str, &'static str> {
        match self {
            Self::File { path } => path.to_str().ok_or("Invalid file name."),
            Self::Service { url, .. } => Ok(url),
        }
    }

    pub fn load(&self, session: Option<&NativeSession>) -> Result<Catalog, &'static str> {
        match self {
            Self::File { path } => local_catalog(path),
            Self::Service { url, sso } => {
                let url = service_url(url)?;
                let client = Client::builder()
                    .redirect(Policy::none())
                    .timeout(Duration::from_secs(10))
                    .build()
                    .map_err(|_| "Cannot initialize configuration client.")?;
                let mut request = client.get(url.clone()).header("Accept", "application/json");
                if *sso {
                    let session = session.ok_or("Sign in to load this configuration.")?;
                    if url.origin() != service_url(&session.origin)?.origin() {
                        return Err("Configuration service must share the SSO origin.");
                    }
                    if url.scheme() == "http"
                        && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
                    {
                        return Err("Use HTTPS for company sign-in.");
                    }
                    request = request.bearer_auth(&session.bearer);
                }
                let response = request
                    .send()
                    .map_err(|_| "Configuration service unavailable.")?;
                if !response.status().is_success() {
                    return Err("Configuration service rejected the request.");
                }
                read_catalog(response)
            }
        }
    }
}
