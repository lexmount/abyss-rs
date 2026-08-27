//! Owner-only Unix Domain Socket listener for macOS and Linux plugins.

use std::{
    io,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use sha2::{Digest as _, Sha256};
use tokio::{
    fs,
    net::{UnixListener, UnixStream},
};

use crate::plugin::PluginServerError;
use crate::plugin::transport::PluginTransport;

const SOCKET_DIRECTORY_MODE: u32 = 0o700;
const SOCKET_FILE_MODE: u32 = 0o600;
const SOCKET_FILE_NAME: &str = "broker-plugin-v1.sock";
const CONSERVATIVE_UNIX_SOCKET_PATH_BYTES: usize = 100;

/// Bound Unix listener and its removable filesystem entry.
pub struct UnixPluginTransport {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl UnixPluginTransport {
    async fn bind_inner(abyss_home: &Path) -> Result<Self, PluginServerError> {
        let socket_path = Self::socket_path(abyss_home);
        Self::create_parent_directory(&socket_path).await?;
        let listener = Self::bind_listener(&socket_path).await?;
        fs::set_permissions(
            &socket_path,
            std::fs::Permissions::from_mode(SOCKET_FILE_MODE),
        )
        .await
        .map_err(|source| {
            PluginServerError::io("configure broker plugin socket permissions", source)
        })?;
        Ok(Self {
            listener,
            socket_path,
        })
    }

    fn socket_path(abyss_home: &Path) -> PathBuf {
        let product_path = abyss_home.join("runtime").join(SOCKET_FILE_NAME);
        if product_path.as_os_str().as_encoded_bytes().len() <= CONSERVATIVE_UNIX_SOCKET_PATH_BYTES
        {
            return product_path;
        }

        let digest = Sha256::digest(abyss_home.as_os_str().as_encoded_bytes());
        let namespace = hex::encode(&digest[..8]);
        Path::new("/tmp").join(format!("abyss-plugin-{namespace}.sock"))
    }

    async fn accept_inner(&self) -> Result<UnixStream, PluginServerError> {
        self.listener
            .accept()
            .await
            .map(|(stream, _address)| stream)
            .map_err(|source| PluginServerError::io("accept broker plugin connection", source))
    }

    fn endpoint_label_inner(&self) -> String {
        self.socket_path.display().to_string()
    }

    async fn shutdown_inner(self) {
        Self::remove_socket_file(&self.socket_path).await;
    }

    async fn create_parent_directory(socket_path: &Path) -> Result<(), PluginServerError> {
        let Some(parent) = socket_path.parent() else {
            return Ok(());
        };
        fs::create_dir_all(parent).await.map_err(|source| {
            PluginServerError::io("create broker plugin socket directory", source)
        })?;
        if parent != Path::new("/tmp") {
            fs::set_permissions(
                parent,
                std::fs::Permissions::from_mode(SOCKET_DIRECTORY_MODE),
            )
            .await
            .map_err(|source| {
                PluginServerError::io(
                    "configure broker plugin socket directory permissions",
                    source,
                )
            })?;
        }
        Ok(())
    }

    async fn bind_listener(socket_path: &Path) -> Result<UnixListener, PluginServerError> {
        let bind_error = match UnixListener::bind(socket_path) {
            Ok(listener) => return Ok(listener),
            Err(source) if source.kind() == io::ErrorKind::AddrInUse => source,
            Err(source) => {
                return Err(PluginServerError::io(
                    "bind broker plugin Unix socket",
                    source,
                ));
            }
        };

        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                drop(stream);
                Err(PluginServerError::io(
                    "bind broker plugin Unix socket",
                    bind_error,
                ))
            }
            Err(source)
                if matches!(
                    source.kind(),
                    io::ErrorKind::ConnectionRefused | io::ErrorKind::NotFound
                ) =>
            {
                if let Err(source) = fs::remove_file(socket_path).await
                    && source.kind() != io::ErrorKind::NotFound
                {
                    return Err(PluginServerError::io(
                        "remove stale broker plugin Unix socket",
                        source,
                    ));
                }
                UnixListener::bind(socket_path).map_err(|source| {
                    PluginServerError::io("bind broker plugin Unix socket", source)
                })
            }
            Err(_source) => Err(PluginServerError::io(
                "bind broker plugin Unix socket",
                bind_error,
            )),
        }
    }

    async fn remove_socket_file(socket_path: &Path) {
        if let Err(error) = fs::remove_file(socket_path).await
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %socket_path.display(),
                %error,
                "failed to remove broker plugin Unix socket"
            );
        }
    }
}

impl PluginTransport for UnixPluginTransport {
    type Stream = UnixStream;

    async fn bind(abyss_home: &Path) -> Result<Self, PluginServerError> {
        Self::bind_inner(abyss_home).await
    }

    async fn accept(&mut self) -> Result<Self::Stream, PluginServerError> {
        self.accept_inner().await
    }

    fn endpoint_label(&self) -> String {
        self.endpoint_label_inner()
    }

    async fn shutdown(self) {
        self.shutdown_inner().await;
    }
}

impl Drop for UnixPluginTransport {
    fn drop(&mut self) {
        if let Err(error) = std::fs::remove_file(&self.socket_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %self.socket_path.display(),
                %error,
                "failed to remove dropped broker plugin Unix socket"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{CONSERVATIVE_UNIX_SOCKET_PATH_BYTES, UnixPluginTransport};

    #[test]
    fn short_product_root_keeps_the_discoverable_runtime_path() {
        assert_eq!(
            UnixPluginTransport::socket_path(Path::new("/tmp/abyss")),
            Path::new("/tmp/abyss/runtime/broker-plugin-v1.sock")
        );
    }

    #[test]
    fn long_product_root_uses_a_bounded_stable_fallback() {
        let root = Path::new(
            "/tmp/this-is-an-intentionally-long-product-root/with/many/components/that/exceed/the/unix-domain-socket/path/limit",
        );
        let first = UnixPluginTransport::socket_path(root);
        let second = UnixPluginTransport::socket_path(root);

        assert_eq!(first, second);
        assert!(first.as_os_str().as_encoded_bytes().len() <= CONSERVATIVE_UNIX_SOCKET_PATH_BYTES);
        assert!(
            first
                .file_stem()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("abyss-plugin-"))
                && first
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("sock"))
        );
    }
}
