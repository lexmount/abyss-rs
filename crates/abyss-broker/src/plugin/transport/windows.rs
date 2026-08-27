//! Windows Named Pipe transport for local broker plugin processes.

use std::{future::Future, path::Path};

use sha2::{Digest as _, Sha256};
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};

use crate::plugin::{PluginServerError, transport::PluginTransport};

const PIPE_NAME_PREFIX: &str = r"\\.\pipe\abyss.broker-plugin-v1";

/// Named Pipe transport that prepares one pending instance for the next client.
pub struct WindowsPluginTransport {
    pipe_name: String,
    pending: Option<NamedPipeServer>,
}

impl WindowsPluginTransport {
    fn create_instance(
        pipe_name: &str,
        first_pipe_instance: bool,
    ) -> Result<NamedPipeServer, PluginServerError> {
        ServerOptions::new()
            .first_pipe_instance(first_pipe_instance)
            .reject_remote_clients(true)
            .create(pipe_name)
            .map_err(|source| PluginServerError::io("create broker plugin Named Pipe", source))
    }

    async fn accept_inner(&mut self) -> Result<NamedPipeServer, PluginServerError> {
        let connected = match self.pending.take() {
            Some(pending) => pending,
            None => Self::create_instance(&self.pipe_name, false)?,
        };
        connected
            .connect()
            .await
            .map_err(|source| PluginServerError::io("accept broker plugin Named Pipe", source))?;

        match Self::create_instance(&self.pipe_name, false) {
            Ok(next) => self.pending = Some(next),
            Err(error) => {
                // The accepted connection is still valid. The next accept call
                // retries pipe creation instead of retaining a connected pipe.
                tracing::warn!(%error, "preparing the next broker plugin Named Pipe failed");
            }
        }
        Ok(connected)
    }
}

impl PluginTransport for WindowsPluginTransport {
    type Stream = NamedPipeServer;

    fn bind(abyss_home: &Path) -> impl Future<Output = Result<Self, PluginServerError>> + Send {
        let pipe_name = pipe_name(abyss_home);
        let transport = Self::create_instance(&pipe_name, true).map(|pending| Self {
            pipe_name,
            pending: Some(pending),
        });
        std::future::ready(transport)
    }

    async fn accept(&mut self) -> Result<Self::Stream, PluginServerError> {
        self.accept_inner().await
    }

    fn endpoint_label(&self) -> String {
        self.pipe_name.clone()
    }

    fn shutdown(self) -> impl Future<Output = ()> + Send {
        std::future::ready(())
    }
}

fn pipe_name(abyss_home: &Path) -> String {
    let normalized_home = abyss_home.to_string_lossy().to_lowercase();
    let digest = Sha256::digest(normalized_home.as_bytes());
    let namespace = hex::encode(&digest[..8]);
    format!("{PIPE_NAME_PREFIX}-{namespace}")
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::pipe_name;

    #[test]
    fn pipe_namespace_is_stable_and_product_scoped() {
        let cli = pipe_name(Path::new(r"C:\Users\test\AppData\Local\Abyss\cli"));
        let host = pipe_name(Path::new(r"C:\ProgramData\Abyss"));

        assert_eq!(
            cli,
            pipe_name(Path::new(r"c:\users\test\appdata\local\abyss\cli"))
        );
        assert_ne!(cli, host);
        assert!(cli.starts_with(r"\\.\pipe\abyss.broker-plugin-v1-"));
    }
}
