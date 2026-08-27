//! Local REST control authentication for `abyss-broker`.

use std::{
    env,
    future::Future,
    net::SocketAddr,
    panic::{AssertUnwindSafe, resume_unwind},
    path::{Path, PathBuf},
};

use futures_util::FutureExt as _;
use rand::RngCore as _;
use tokio::{fs, io::AsyncWriteExt as _};

use crate::{error::BrokerError, platform::PlatformAdapter};

const TOKEN_BYTES: usize = 32;

/// Per-process bearer token written to disk for the platform wrapper.
pub struct AuthTokenFile {
    path: PathBuf,
    token: String,
}

impl AuthTokenFile {
    /// Creates a fresh bearer token file for the current broker process.
    ///
    /// # Errors
    ///
    /// Returns an error when token generation or file creation fails.
    pub async fn create(path: PathBuf) -> Result<Self, BrokerError> {
        let token = tokio::task::spawn_blocking(generate_token)
            .await
            .map_err(|source| BrokerError::task("generate broker auth token", source))?;
        write_token_file(&path, &token).await?;
        Ok(Self { path, token })
    }

    /// Returns the bearer token that REST mutating endpoints must receive.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Removes the bearer token file before broker shutdown completes.
    pub async fn remove(self) {
        remove_token_file(&self.path).await;
    }

    /// Runs broker work, then removes the token before returning or resuming a panic.
    pub async fn run_with_cleanup<F, T>(self, future: F) -> T
    where
        F: Future<Output = T>,
    {
        let result = AssertUnwindSafe(future).catch_unwind().await;
        self.remove().await;
        match result {
            Ok(output) => output,
            Err(panic) => resume_unwind(panic),
        }
    }
}

/// Default token file path used when callers do not pass an explicit path.
#[must_use]
pub fn default_auth_token_file(api_addr: SocketAddr, platform: &dyn PlatformAdapter) -> PathBuf {
    runtime_dir(platform).join(format!("broker-{}.token", sanitize_socket_addr(api_addr)))
}

async fn write_token_file(path: &Path, token: &str) -> Result<(), BrokerError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .await
            .map_err(|source| BrokerError::io("create broker auth token directory", source))?;
    }

    let write_result = async {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .await
            .map_err(|source| BrokerError::io("create broker auth token file", source))?;
        file.write_all(token.as_bytes())
            .await
            .map_err(|source| BrokerError::io("write broker auth token file", source))?;
        file.flush()
            .await
            .map_err(|source| BrokerError::io("flush broker auth token file", source))
    }
    .await;
    if write_result.is_err() {
        remove_token_file(path).await;
    }
    write_result
}

async fn remove_token_file(path: &Path) {
    if let Err(error) = fs::remove_file(path).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::warn!(
            path = %path.display(),
            %error,
            "failed to remove broker auth token file"
        );
    }
}

fn generate_token() -> String {
    let mut bytes = [0_u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    encode_hex(&bytes)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let capacity = bytes
        .len()
        .checked_mul(2_usize)
        .expect("hex output capacity should not overflow");
    let mut encoded = String::with_capacity(capacity);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4_u8)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f_u8)]));
    }
    encoded
}

fn runtime_dir(platform: &dyn PlatformAdapter) -> PathBuf {
    env::var_os("ABYSS_BROKER_RUNTIME_DIR")
        .map_or_else(|| platform.abyss_home().join("runtime"), PathBuf::from)
}

fn sanitize_socket_addr(api_addr: SocketAddr) -> String {
    api_addr
        .to_string()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tokio::fs;

    use super::{AuthTokenFile, default_auth_token_file, encode_hex};

    #[tokio::test]
    async fn token_file_is_written_and_removed() {
        let path = test_token_path("token-file-is-written-and-removed");
        let token_file = AuthTokenFile::create(path.clone())
            .await
            .expect("token file should be created");

        let token = fs::read_to_string(&path)
            .await
            .expect("token file should be readable");
        assert_eq!(token, token_file.token());
        assert_eq!(token.len(), 64);

        token_file.remove().await;
        assert!(
            !fs::try_exists(path)
                .await
                .expect("token path should be queryable"),
            "token file should be removed when broker exits"
        );
    }

    #[tokio::test]
    async fn token_file_is_removed_before_a_wrapped_panic_resumes() {
        let path = test_token_path("token-file-is-removed-after-panic");
        let token_file = AuthTokenFile::create(path.clone())
            .await
            .expect("token file should be created");

        let cleanup_task = tokio::spawn(async move {
            token_file
                .run_with_cleanup(async {
                    panic!("test broker panic");
                })
                .await;
        });
        let error = cleanup_task
            .await
            .expect_err("wrapped broker panic should resume after cleanup");
        assert!(error.is_panic());
        assert!(
            !fs::try_exists(path)
                .await
                .expect("token path should be queryable"),
            "token file should be removed before the panic resumes"
        );
    }

    #[tokio::test]
    async fn token_file_replaces_stale_contents() {
        let path = test_token_path("token-file-replaces-stale-contents");
        fs::write(&path, "stale-token")
            .await
            .expect("stale token file should be written");

        let token_file = AuthTokenFile::create(path.clone())
            .await
            .expect("token file should be replaced");
        let contents = fs::read_to_string(&path)
            .await
            .expect("replacement token file should be readable");
        assert_eq!(contents, token_file.token());
        assert_ne!(contents, "stale-token");

        token_file.remove().await;
    }

    #[test]
    fn default_token_path_is_api_specific() {
        let platform = crate::platform::platform_adapter();
        let first = default_auth_token_file(
            "127.0.0.1:18190"
                .parse()
                .expect("test address should parse"),
            platform.as_ref(),
        );
        let second = default_auth_token_file(
            "127.0.0.1:18191"
                .parse()
                .expect("test address should parse"),
            platform.as_ref(),
        );

        assert_ne!(first, second);
    }

    #[test]
    fn hex_encoding_is_stable() {
        assert_eq!(encode_hex(&[0x00, 0x0f, 0xf0, 0xff]), "000ff0ff");
    }

    fn test_token_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("abyss-broker-{name}-{}.token", std::process::id()))
    }
}
