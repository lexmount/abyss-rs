//! Platform-local plugin transport abstraction.
//!
//! Unix Domain Socket and Windows Named Pipe details stay behind the same
//! listener lifecycle used by the broker plugin server.

#[cfg(unix)]
mod unix;
#[cfg(target_os = "windows")]
mod windows;

use std::{future::Future, path::Path};

use tokio::io::{AsyncRead, AsyncWrite};

use super::PluginServerError;

/// Target-selected concrete plugin transport.
pub mod platform {
    #[cfg(unix)]
    pub use super::unix::UnixPluginTransport as PlatformPluginTransport;
    #[cfg(target_os = "windows")]
    pub use super::windows::WindowsPluginTransport as PlatformPluginTransport;
}

/// Broker-side listener for one platform-local plugin transport.
pub trait PluginTransport: Send + Sized {
    /// Accepted bidirectional byte stream.
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// Binds the product-scoped platform endpoint.
    fn bind(abyss_home: &Path) -> impl Future<Output = Result<Self, PluginServerError>> + Send;

    /// Accepts one plugin connection.
    fn accept(&mut self) -> impl Future<Output = Result<Self::Stream, PluginServerError>> + Send;

    /// Returns the concrete endpoint advertised through broker startup info.
    fn endpoint_label(&self) -> String;

    /// Releases transport-specific resources after the accept loop stops.
    fn shutdown(self) -> impl Future<Output = ()> + Send;
}
