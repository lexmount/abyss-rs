//! Platform-local stream connection used by the plugin runtime.

use std::{io, pin::Pin};

use tokio::io::{AsyncRead, AsyncWrite};

pub(super) trait PluginStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> PluginStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(super) type ConnectedPluginStream = Pin<Box<dyn PluginStream>>;

#[cfg(unix)]
pub(super) async fn connect(endpoint: &str) -> io::Result<ConnectedPluginStream> {
    let stream = tokio::net::UnixStream::connect(endpoint).await?;
    let stream: ConnectedPluginStream = Box::pin(stream);
    Ok(stream)
}

#[cfg(target_os = "windows")]
pub(super) fn connect(endpoint: &str) -> std::future::Ready<io::Result<ConnectedPluginStream>> {
    let connected = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(endpoint)
        .map(|stream| {
            let stream: ConnectedPluginStream = Box::pin(stream);
            stream
        });
    std::future::ready(connected)
}
