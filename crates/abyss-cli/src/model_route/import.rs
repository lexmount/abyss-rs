//! Open catalog sources using the CLI user's filesystem and login.
use std::{fs::File, io::Read, path::Path, time::Duration};

use abyss_terminal_auth::CredentialStore as _;
use reqwest::{Url, blocking::Client, redirect::Policy};
use serde_json::{Value, json};

use crate::{credential::CliCredentialStore, error::CliError, paths::CliPaths};

fn read_catalog(reader: impl Read) -> Result<Value, CliError> {
    const LIMIT: u32 = 2 * 1024 * 1024;
    let mut bytes = Vec::new();
    reader.take(u64::from(LIMIT) + 1).read_to_end(&mut bytes)?;
    if bytes.len() > usize::try_from(LIMIT).unwrap_or(usize::MAX) {
        return Err(CliError::InvalidConfiguration(
            "Model route document exceeds the size limit.".into(),
        ));
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| CliError::InvalidConfiguration("Invalid model route JSON.".into()))
}

pub(super) fn file(path: &Path) -> Result<Value, CliError> {
    let path = path.canonicalize()?;
    if !path
        .extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        || !path.is_file()
    {
        return Err(CliError::InvalidConfiguration(
            "Select a regular .json file.".into(),
        ));
    }
    Ok(json!({"source":path, "catalog":read_catalog(File::open(&path)?)?}))
}

pub(super) fn service(paths: &CliPaths, source: &str, sso: bool) -> Result<Value, CliError> {
    let invalid = |message: &str| CliError::InvalidConfiguration(message.into());
    let url = Url::parse(source).map_err(|_| invalid("Invalid catalog URL."))?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.has_host()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid(
            "Expected an HTTP or HTTPS catalog URL without credentials.",
        ));
    }
    let client = Client::builder()
        .redirect(Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .map_err(|_| invalid("Cannot initialize configuration client."))?;
    let mut request = client.get(url.clone()).header("accept", "application/json");
    if sso {
        let login = CliCredentialStore::from_paths(paths)?.read()?;
        if login.expires_at <= jiff::Timestamp::now() {
            return Err(invalid("Sign in again to import this catalog."));
        }
        if Url::parse(&login.control_plane)
            .map_err(|_| invalid("Invalid SSO issuer."))?
            .origin()
            != url.origin()
            || (url.scheme() == "http"
                && !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")))
        {
            return Err(invalid("Catalog URL must share the secure SSO origin."));
        }
        request = request.bearer_auth(login.token);
    }
    let response = request
        .send()
        .map_err(|_| invalid("Configuration service unavailable."))?;
    if !response.status().is_success() {
        return Err(invalid("Configuration service rejected the request."));
    }
    Ok(json!({"source":source,"catalog":read_catalog(response)?}))
}
