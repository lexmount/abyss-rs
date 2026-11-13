//! Versioned profile persistence; configuration contains references, never tokens.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use abyss_data_client::{ApiEndpoint, DataClientOptions};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    args::{AuthMode, CredentialStore, ProfileAdd, ProfileCommand},
    error::QueryError as Error,
};

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub endpoint: String,
    #[serde(default)]
    pub allow_http: bool,
    pub auth: Authentication,
    pub ca_file: Option<PathBuf>,
    pub timeout: u64,
    pub max_response_bytes: usize,
    pub retries: u8,
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum Authentication {
    None,
    Bearer {
        source: TokenSource,
    },
    Terminal {
        endpoint: String,
        store: CredentialStore,
    },
}
#[derive(Deserialize, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum TokenSource {
    Env(String),
    File(PathBuf),
    HeaderFile(PathBuf),
}

impl Profile {
    pub fn from_args(args: &ProfileAdd) -> Result<Self, Error> {
        validate_name(&args.name)?;
        let source = match (&args.token_env, &args.token_file, &args.header_file) {
            (Some(name), None, None) if !name.is_empty() && !name.contains(['=', '\0']) => {
                Some(TokenSource::Env(name.clone()))
            }
            (None, Some(path), None) => Some(TokenSource::File(absolute(path)?)),
            (None, None, Some(path)) => Some(TokenSource::HeaderFile(absolute(path)?)),
            (None, None, None) => None,
            _ => return Err(Error::Config("select exactly one valid bearer source")),
        };
        let auth = match (args.auth, source, &args.auth_endpoint) {
            (AuthMode::None, None, None) => Authentication::None,
            (AuthMode::Bearer, Some(source), None) => Authentication::Bearer { source },
            (AuthMode::Terminal, None, Some(endpoint)) => Authentication::Terminal {
                endpoint: ApiEndpoint::parse_with_http(endpoint, args.allow_http)?
                    .as_str()
                    .into(),
                store: args.credential_store,
            },
            _ => {
                return Err(Error::Config(
                    "none accepts no credentials; bearer requires a token source; terminal requires --auth-endpoint",
                ));
            }
        };
        if !matches!(args.auth, AuthMode::Terminal)
            && !matches!(args.credential_store, CredentialStore::Keyring)
        {
            return Err(Error::Config(
                "--credential-store applies only to terminal auth",
            ));
        }
        let profile = Self {
            endpoint: ApiEndpoint::parse_with_http(&args.endpoint, args.allow_http)?
                .as_str()
                .into(),
            auth,
            allow_http: args.allow_http,
            ca_file: args.ca_file.as_deref().map(absolute).transpose()?,
            timeout: args.timeout,
            max_response_bytes: args.max_response_bytes,
            retries: args.retries,
        };
        // Validate transport budgets and CA before persisting a usable profile.
        let options = profile.options()?;
        abyss_data_client::HttpTransport::new(
            options.timeout,
            options.max_response_bytes,
            options.ca_pem.as_deref(),
            options.retries,
        )?;
        Ok(profile)
    }
    pub fn options(&self) -> Result<DataClientOptions, Error> {
        Ok(DataClientOptions {
            timeout: std::time::Duration::from_secs(self.timeout),
            max_response_bytes: self.max_response_bytes,
            ca_pem: self
                .ca_file
                .as_deref()
                .map(|path| read_bounded(path, 1024 * 1024))
                .transpose()?,
            retries: self.retries,
        })
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    version: u32,
    active: Option<String>,
    profiles: BTreeMap<String, Profile>,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            version: 1_u32,
            active: None,
            profiles: BTreeMap::new(),
        }
    }
}
impl Config {
    pub fn selected(&self, name: Option<&str>) -> Result<(&str, &Profile), Error> {
        let name = name.or(self.active.as_deref()).ok_or(Error::Config(
            "no active profile; use profile add and profile use",
        ))?;
        self.profiles
            .get_key_value(name)
            .map(|(key, value)| (key.as_str(), value))
            .ok_or(Error::Config("profile does not exist"))
    }
}

pub struct ConfigFile {
    pub path: PathBuf,
}
impl ConfigFile {
    pub fn new(path: Option<&Path>) -> Result<Self, Error> {
        let path = match path {
            Some(path) => absolute(path)?,
            None => directories::ProjectDirs::from("net", "lexmount", "abyss-query")
                .ok_or(Error::Config(
                    "cannot locate config directory; set --config",
                ))?
                .config_dir()
                .join("profiles.json"),
        };
        Ok(Self { path })
    }
    pub fn read(&self) -> Result<Config, Error> {
        let bytes = match read_bounded(&self.path, 1024 * 1024) {
            Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Config::default());
            }
            result => result?,
        };
        let config: Config = serde_json::from_slice(&bytes)?;
        if config.version != 1 {
            return Err(Error::Config("unsupported profile configuration version"));
        }
        Ok(config)
    }
    pub fn command(
        &self,
        command: &ProfileCommand,
        selected: Option<&str>,
    ) -> Result<Value, Error> {
        match command {
            ProfileCommand::List => return Ok(serde_json::to_value(self.read()?)?),
            ProfileCommand::Show { name } => {
                return Ok(serde_json::to_value(
                    self.read()?.selected(name.as_deref().or(selected))?.1,
                )?);
            }
            _ => {}
        }
        let parent = self
            .path
            .parent()
            .ok_or(Error::Config("config path has no parent"))?;
        fs::create_dir_all(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.path.with_extension("lock"))?;
        lock.lock()?;
        let mut config = self.read()?;
        match command {
            ProfileCommand::Add(args) => {
                if config.profiles.contains_key(&args.name) {
                    return Err(Error::Config(
                        "profile exists; remove it before replacing its endpoint or auth policy",
                    ));
                }
                config
                    .profiles
                    .insert(args.name.clone(), Profile::from_args(args)?);
                if config.active.is_none() {
                    config.active = Some(args.name.clone());
                }
            }
            ProfileCommand::Use { name } => {
                config.selected(Some(name))?;
                config.active = Some(name.clone());
            }
            ProfileCommand::Remove { name } => {
                let (_, profile) = config.selected(Some(name))?;
                if let Authentication::Terminal { .. } = profile.auth {
                    crate::credentials::CredentialVault::new(self, name, profile)?.remove()?;
                }
                config.profiles.remove(name);
                if config.active.as_ref() == Some(name) {
                    config.active = None;
                }
            }
            ProfileCommand::List | ProfileCommand::Show { .. } => {
                unreachable!("read commands returned above")
            }
        }
        atomic_write(&self.path, &serde_json::to_vec_pretty(&config)?)?;
        Ok(json!({"ok":true,"active":config.active}))
    }
}

pub fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(Error::Config("local file exceeds its size budget"));
    }
    Ok(bytes)
}
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let parent = path
        .parent()
        .ok_or(Error::Config("file path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    temp.persist(path).map_err(|error| Error::Io(error.error))?;
    #[cfg(unix)]
    File::open(parent)?.sync_all()?;
    Ok(())
}
fn validate_name(name: &str) -> Result<(), Error> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(Error::Config(
            "profile names must contain 1..64 ASCII letters, digits, hyphens or underscores",
        ));
    }
    Ok(())
}
fn absolute(path: &Path) -> Result<PathBuf, Error> {
    if path.is_absolute() {
        Ok(path.into())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}
