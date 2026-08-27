//! Ingress abstractions for broker-owned traffic entry points.
//!
//! Each ingress owns listening and protocol- or platform-specific connection
//! preparation. The proxy worker consumes normalized `PlatformFlow` values and
//! keeps MITM handling independent from explicit HTTP proxying, WFP, Network
//! Extension, or future IPC transport details.

pub mod explicit;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use std::{future::Future, net::SocketAddr, path::Path};

#[cfg(target_os = "windows")]
use std::error::Error;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::io;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::net::TcpStream;

use crate::connection::OriginalDestination;

/// Target-specific transparent ingress types available to the broker.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub mod platform {
    #[cfg(target_os = "macos")]
    pub use super::macos::IngressEndpoint as TransparentIngressEndpoint;
    #[cfg(target_os = "windows")]
    pub use super::windows::IngressEndpoint as TransparentIngressEndpoint;
}

/// Proxy modes supported by the current operating-system build.
#[derive(Debug, Clone, Copy, clap::ValueEnum, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMode {
    /// Accept opt-in clients through an HTTP explicit proxy listener.
    Explicit,
    /// Accept connections from the operating-system transparent adapter.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Transparent,
}

/// Validated ingress endpoints for one broker proxy runtime.
#[derive(Debug, Clone, PartialEq)]
pub enum ProxyPlan {
    /// One explicit HTTP proxy listener.
    Explicit {
        /// Explicit proxy endpoint.
        explicit: explicit::ExplicitIngressEndpoint,
    },
    /// One platform transparent ingress.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    Transparent {
        /// Platform transparent endpoint.
        transparent: platform::TransparentIngressEndpoint,
    },
}

impl ProxyPlan {
    /// Creates an explicit-only proxy plan.
    #[must_use]
    pub const fn explicit(endpoint: explicit::ExplicitIngressEndpoint) -> Self {
        Self::Explicit { explicit: endpoint }
    }

    /// Creates a transparent-only proxy plan.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[must_use]
    pub const fn transparent(endpoint: platform::TransparentIngressEndpoint) -> Self {
        Self::Transparent {
            transparent: endpoint,
        }
    }

    /// Returns the mode represented by this plan.
    #[must_use]
    pub const fn mode(&self) -> ProxyMode {
        match self {
            Self::Explicit { .. } => ProxyMode::Explicit,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Transparent { .. } => ProxyMode::Transparent,
        }
    }

    /// Returns a compact requested-endpoint label for logs and errors.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        match self {
            Self::Explicit { explicit } => explicit.endpoint_label(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            Self::Transparent { transparent } => transparent.endpoint_label(),
        }
    }
}

/// Stable ingress identity exposed in status and diagnostics.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressSource {
    /// Local HTTP explicit proxy listener.
    ExplicitHttp,
    /// macOS Network Extension framed-flow ingress.
    #[cfg(target_os = "macos")]
    MacosNetworkExtension,
    /// Windows WFP redirected TCP ingress.
    #[cfg(target_os = "windows")]
    WindowsWfp,
}

/// Bound runtime endpoint for one ingress worker.
///
/// Each variant carries the endpoint required by that ingress. This prevents
/// impossible combinations such as a macOS Unix ingress with a TCP listener or
/// a TCP ingress without a bound address.
#[derive(Debug, Clone)]
pub enum IngressRuntimeStatus {
    /// Local explicit HTTP proxy listener.
    ExplicitHttp {
        /// Bound loopback TCP address.
        listen_addr: SocketAddr,
    },
    /// macOS Network Extension framed-flow Unix socket.
    #[cfg(target_os = "macos")]
    MacosNetworkExtension {
        /// Bound Unix socket path.
        socket_path: PathBuf,
    },
    /// Windows WFP redirected TCP listener.
    #[cfg(target_os = "windows")]
    WindowsWfp {
        /// Bound loopback TCP address.
        listen_addr: SocketAddr,
    },
}

impl IngressRuntimeStatus {
    /// Creates explicit HTTP proxy status.
    #[must_use]
    pub const fn explicit_http(listen_addr: SocketAddr) -> Self {
        Self::ExplicitHttp { listen_addr }
    }

    /// Creates macOS Network Extension status.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub const fn macos_network_extension(socket_path: PathBuf) -> Self {
        Self::MacosNetworkExtension { socket_path }
    }

    /// Creates Windows WFP redirect status.
    #[cfg(target_os = "windows")]
    #[must_use]
    pub const fn windows_wfp(listen_addr: SocketAddr) -> Self {
        Self::WindowsWfp { listen_addr }
    }

    /// Returns the stable ingress implementation identity.
    #[must_use]
    pub const fn source(&self) -> IngressSource {
        match self {
            Self::ExplicitHttp { .. } => IngressSource::ExplicitHttp,
            #[cfg(target_os = "macos")]
            Self::MacosNetworkExtension { .. } => IngressSource::MacosNetworkExtension,
            #[cfg(target_os = "windows")]
            Self::WindowsWfp { .. } => IngressSource::WindowsWfp,
        }
    }

    /// Returns the bound TCP address for TCP-based ingress variants.
    #[must_use]
    // The optional return type keeps this cross-platform status API uniform;
    // macOS also has a Unix-socket variant with no TCP address.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::unnecessary_wraps,
            reason = "the status API has the same optional shape on every platform"
        )
    )]
    pub const fn listen_addr(&self) -> Option<SocketAddr> {
        match self {
            Self::ExplicitHttp { listen_addr } => Some(*listen_addr),
            #[cfg(target_os = "macos")]
            Self::MacosNetworkExtension { .. } => None,
            #[cfg(target_os = "windows")]
            Self::WindowsWfp { listen_addr } => Some(*listen_addr),
        }
    }

    /// Returns the bound Unix socket path for filesystem-based ingress variants.
    #[must_use]
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::missing_const_for_fn,
            reason = "macOS PathBuf-to-Path conversion is not const"
        )
    )]
    pub fn socket_path(&self) -> Option<&Path> {
        match self {
            Self::ExplicitHttp { .. } => None,
            #[cfg(target_os = "macos")]
            Self::MacosNetworkExtension { socket_path } => Some(socket_path),
            #[cfg(target_os = "windows")]
            Self::WindowsWfp { .. } => None,
        }
    }

    /// Returns a compact bound-endpoint label.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.listen_addr().map_or_else(
            || {
                self.socket_path()
                    .map_or_else(|| "<unbound>".to_owned(), |path| path.display().to_string())
            },
            |address| address.to_string(),
        )
    }
}

impl Serialize for IngressRuntimeStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        #[derive(Serialize)]
        struct IngressRuntimeStatusResponse<'a> {
            source: IngressSource,
            listen_addr: Option<SocketAddr>,
            #[serde(skip_serializing_if = "Option::is_none")]
            socket_path: Option<&'a Path>,
        }

        IngressRuntimeStatusResponse {
            source: self.source(),
            listen_addr: self.listen_addr(),
            socket_path: self.socket_path(),
        }
        .serialize(serializer)
    }
}

/// Starts one broker ingress source.
pub trait IngressFactory: Send {
    /// Concrete ingress returned after startup.
    type Ingress: Ingress + 'static;

    /// Starts the concrete ingress source.
    fn start(
        self,
    ) -> impl Future<Output = Result<StartedIngress<Self::Ingress>, IngressError>> + Send;
}

/// Broker-side listener for one traffic source.
pub trait Ingress: Send {
    /// Accepted connection type prepared outside the listener accept loop.
    type Accepted: IngressConnection + 'static;

    /// Accepts one client connection without parsing its application protocol.
    fn accept(&mut self) -> impl Future<Output = Result<Self::Accepted, IngressError>> + Send;

    /// Releases asynchronous resources owned by the listener.
    fn shutdown(self) -> impl Future<Output = ()> + Send
    where
        Self: Sized,
    {
        std::future::ready(())
    }
}

/// Accepted ingress connection that can produce one normalized flow.
pub trait IngressConnection: Send {
    /// Performs connection-specific parsing and destination recovery.
    fn into_flow(self) -> impl Future<Output = Result<PlatformFlow, IngressError>> + Send;
}

/// Started ingress plus its bound runtime status.
pub struct StartedIngress<I> {
    ingress: I,
    status: IngressRuntimeStatus,
}

impl<I> StartedIngress<I> {
    /// Creates a started ingress bundle.
    #[must_use]
    pub const fn new(ingress: I, status: IngressRuntimeStatus) -> Self {
        Self { ingress, status }
    }

    /// Splits the ingress runtime from its status.
    #[must_use]
    pub fn into_parts(self) -> (I, IngressRuntimeStatus) {
        (self.ingress, self.status)
    }
}

/// Metadata recovered by a platform ingress before MITM handling.
pub struct PlatformFlowMetadata {
    flow_id: abyss_mitm::FlowId,
    peer_addr: Option<SocketAddr>,
    local_addr: Option<SocketAddr>,
    original_destination: OriginalDestination,
    destination_host: Option<String>,
    source_process: Option<abyss_mitm::SourceProcess>,
}

impl PlatformFlowMetadata {
    /// Creates platform flow metadata from normalized optional fields.
    #[must_use]
    pub fn from_parts(
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        original_destination: OriginalDestination,
        destination_host: Option<String>,
        source_process: Option<abyss_mitm::SourceProcess>,
    ) -> Self {
        Self {
            flow_id: abyss_mitm::FlowId::generate(),
            peer_addr,
            local_addr,
            original_destination,
            destination_host,
            source_process,
        }
    }

    /// Replaces the generated identity with the value supplied by the ingress.
    #[cfg(target_os = "macos")]
    #[must_use]
    pub const fn with_flow_id(mut self, flow_id: abyss_mitm::FlowId) -> Self {
        self.flow_id = flow_id;
        self
    }

    /// Returns the client-side socket address observed by the ingress listener.
    #[must_use]
    pub const fn peer_addr(&self) -> Option<SocketAddr> {
        self.peer_addr
    }

    /// Returns the local listener address that accepted the flow.
    #[must_use]
    pub const fn local_addr(&self) -> Option<SocketAddr> {
        self.local_addr
    }

    /// Returns the destination captured before platform redirection.
    #[must_use]
    pub const fn original_destination(&self) -> &OriginalDestination {
        &self.original_destination
    }

    /// Returns the destination host supplied by the platform adapter when known.
    #[must_use]
    pub fn destination_host(&self) -> Option<&str> {
        self.destination_host.as_deref()
    }

    /// Returns source process metadata when the platform adapter supplied it.
    #[must_use]
    pub const fn source_process(&self) -> Option<&abyss_mitm::SourceProcess> {
        self.source_process.as_ref()
    }
}

/// Accepted platform flow after OS-specific metadata has been recovered.
pub struct PlatformFlow {
    metadata: PlatformFlowMetadata,
    io: abyss_mitm::BoxedDuplexStream,
    ingress: abyss_mitm::FlowIngress,
    prepared_upstream: Option<TcpStream>,
    read_prefix: Box<[u8]>,
}

impl PlatformFlow {
    /// Creates a normalized platform flow.
    #[must_use]
    pub fn new<I>(io: I, metadata: PlatformFlowMetadata) -> Self
    where
        I: abyss_mitm::DuplexStream + 'static,
    {
        Self::from_boxed(Box::new(io), metadata)
    }

    /// Creates a normalized platform flow from a boxed duplex stream.
    #[must_use]
    pub fn from_boxed(io: abyss_mitm::BoxedDuplexStream, metadata: PlatformFlowMetadata) -> Self {
        Self {
            metadata,
            io,
            ingress: abyss_mitm::FlowIngress::transparent(
                abyss_mitm::TransparentFlowSource::Unattributed,
            ),
            prepared_upstream: None,
            read_prefix: Box::default(),
        }
    }

    /// Attaches the normalized ingress description used by the MITM pipeline.
    #[must_use]
    pub fn with_ingress(mut self, ingress: abyss_mitm::FlowIngress) -> Self {
        self.ingress = ingress;
        self
    }

    /// Attaches an upstream socket prepared by an explicit proxy connection.
    #[must_use]
    pub fn with_prepared_upstream(mut self, upstream: TcpStream) -> Self {
        self.prepared_upstream = Some(upstream);
        self
    }

    /// Replays bytes consumed while preparing the ingress connection.
    #[must_use]
    pub fn with_read_prefix(mut self, prefix: Box<[u8]>) -> Self {
        self.read_prefix = prefix;
        self
    }

    /// Returns the normalized ingress metadata used by diagnostics and hooks.
    #[must_use]
    pub const fn ingress(&self) -> &abyss_mitm::FlowIngress {
        &self.ingress
    }

    /// Returns the client-side socket address observed by the ingress listener.
    #[must_use]
    pub const fn peer_addr(&self) -> Option<SocketAddr> {
        self.metadata.peer_addr()
    }

    /// Returns the local listener address that accepted the flow.
    #[must_use]
    pub const fn local_addr(&self) -> Option<SocketAddr> {
        self.metadata.local_addr()
    }

    /// Returns the destination captured before platform redirection.
    #[must_use]
    pub const fn original_destination(&self) -> &OriginalDestination {
        self.metadata.original_destination()
    }

    /// Returns the destination host supplied by the platform adapter when known.
    #[must_use]
    pub fn destination_host(&self) -> Option<&str> {
        self.metadata.destination_host()
    }

    /// Returns source process metadata when available.
    #[must_use]
    pub const fn source_process(&self) -> Option<&abyss_mitm::SourceProcess> {
        self.metadata.source_process()
    }

    /// Converts this platform flow into the current MITM transparent TCP input.
    #[must_use]
    pub fn into_mitm_flow(self) -> abyss_mitm::AcceptedTcpFlow {
        let mut flow = abyss_mitm::AcceptedTcpFlow::from_boxed_parts(
            self.io,
            self.metadata.peer_addr(),
            self.metadata.local_addr(),
            abyss_mitm::OriginalDestination {
                ip: self.metadata.original_destination().ip,
                port: self.metadata.original_destination().port,
            },
            self.metadata.source_process,
        )
        .with_flow_id(self.metadata.flow_id)
        .with_destination_host(self.metadata.destination_host)
        .with_ingress(self.ingress);
        if let Some(upstream) = self.prepared_upstream {
            flow = flow.with_prepared_upstream(upstream);
        }
        flow.with_read_prefix(self.read_prefix)
    }
}

impl IngressConnection for PlatformFlow {
    fn into_flow(self) -> impl Future<Output = Result<Self, IngressError>> + Send {
        std::future::ready(Ok(self))
    }
}

/// Errors raised while accepting or normalizing ingress connections.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IngressError {
    /// An ingress-specific blocking system operation could not be joined.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[error("ingress task failed during {operation}: {source}")]
    Task {
        operation: &'static str,
        #[source]
        source: tokio::task::JoinError,
    },
    /// Explicit HTTP proxy connection preparation failed.
    #[error("explicit HTTP proxy ingress error: {0}")]
    Explicit(#[from] explicit::ExplicitIngressError),
    /// Binding the platform listener failed.
    #[cfg(target_os = "windows")]
    #[error("bind platform ingress listener at {listen_addr}: {source}")]
    Bind {
        listen_addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    /// Creating the directory that will contain a Unix socket failed.
    #[cfg(target_os = "macos")]
    #[error("create platform ingress socket directory `{path}`: {source}")]
    CreateSocketDirectory {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Binding a Unix socket platform listener failed.
    #[cfg(target_os = "macos")]
    #[error("bind platform ingress Unix socket at `{socket_path}`: {source}")]
    BindUnixSocket {
        socket_path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Removing a stale Unix socket before rebinding failed.
    #[cfg(target_os = "macos")]
    #[error("remove stale platform ingress Unix socket at `{socket_path}`: {source}")]
    RemoveStaleUnixSocket {
        socket_path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Configuring Unix socket filesystem permissions failed.
    #[cfg(target_os = "macos")]
    #[error("configure platform ingress Unix socket permissions at `{socket_path}`: {source}")]
    ConfigureUnixSocketPermissions {
        socket_path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Reading the concrete listener address failed.
    #[cfg(target_os = "windows")]
    #[error("read platform ingress listener address: {source}")]
    ListenerAddress {
        #[source]
        source: io::Error,
    },
    /// Accepting a platform connection failed.
    #[cfg(target_os = "windows")]
    #[error("accept platform ingress connection: {source}")]
    Accept {
        #[source]
        source: io::Error,
    },
    /// Accepting a Unix socket platform connection failed.
    #[cfg(target_os = "macos")]
    #[error("accept platform ingress Unix socket connection at `{socket_path}`: {source}")]
    AcceptUnixSocket {
        socket_path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// Reading accepted socket metadata failed.
    #[cfg(target_os = "windows")]
    #[error("read accepted flow local address for {peer_addr}: {source}")]
    LocalAddress {
        peer_addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    /// Querying or decoding the Windows WFP redirect context failed.
    #[cfg(target_os = "windows")]
    #[error("read Windows redirect context for {peer_addr} via {local_addr}: {source}")]
    RedirectContext {
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        #[source]
        source: Box<dyn Error + Send + Sync>,
    },
    /// Resolving host metadata from a framed platform flow failed.
    #[cfg(target_os = "macos")]
    #[error("resolve framed flow destination `{host}:{port}`: {source}")]
    ResolveDestination {
        host: String,
        port: u16,
        #[source]
        source: io::Error,
    },
    /// A framed platform flow was not usable as a normalized TCP flow.
    #[cfg(target_os = "macos")]
    #[error("invalid framed platform flow: {reason}")]
    InvalidFramedFlow { reason: &'static str },
    /// The framed platform flow protocol failed.
    #[cfg(target_os = "macos")]
    #[error("framed platform protocol error during {operation}: {source}")]
    FramedProtocol {
        operation: &'static str,
        #[source]
        source: macos::FlowProtocolError,
    },
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl IngressError {
    pub const fn task(operation: &'static str, source: tokio::task::JoinError) -> Self {
        Self::Task { operation, source }
    }
}

#[cfg(target_os = "windows")]
impl IngressError {
    pub const fn bind(listen_addr: SocketAddr, source: io::Error) -> Self {
        Self::Bind {
            listen_addr,
            source,
        }
    }

    pub const fn listener_address(source: io::Error) -> Self {
        Self::ListenerAddress { source }
    }

    pub const fn accept(source: io::Error) -> Self {
        Self::Accept { source }
    }

    pub const fn local_address(peer_addr: SocketAddr, source: io::Error) -> Self {
        Self::LocalAddress { peer_addr, source }
    }

    pub fn redirect_context<E>(peer_addr: SocketAddr, local_addr: SocketAddr, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        Self::RedirectContext {
            peer_addr,
            local_addr,
            source: Box::new(source),
        }
    }
}

#[cfg(target_os = "macos")]
impl IngressError {
    pub const fn create_socket_directory(path: PathBuf, source: io::Error) -> Self {
        Self::CreateSocketDirectory { path, source }
    }

    pub const fn bind_unix_socket(socket_path: PathBuf, source: io::Error) -> Self {
        Self::BindUnixSocket {
            socket_path,
            source,
        }
    }

    pub const fn remove_stale_unix_socket(socket_path: PathBuf, source: io::Error) -> Self {
        Self::RemoveStaleUnixSocket {
            socket_path,
            source,
        }
    }

    pub const fn configure_unix_socket_permissions(
        socket_path: PathBuf,
        source: io::Error,
    ) -> Self {
        Self::ConfigureUnixSocketPermissions {
            socket_path,
            source,
        }
    }

    pub const fn accept_unix_socket(socket_path: PathBuf, source: io::Error) -> Self {
        Self::AcceptUnixSocket {
            socket_path,
            source,
        }
    }

    pub const fn resolve_destination(host: String, port: u16, source: io::Error) -> Self {
        Self::ResolveDestination { host, port, source }
    }

    pub const fn invalid_framed_flow(reason: &'static str) -> Self {
        Self::InvalidFramedFlow { reason }
    }

    pub const fn framed_protocol(
        operation: &'static str,
        source: macos::FlowProtocolError,
    ) -> Self {
        Self::FramedProtocol { operation, source }
    }
}
