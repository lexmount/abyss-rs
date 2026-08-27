//! Loopback TCP ingress for Windows WFP connect redirection.

use std::net::SocketAddr;

use abyss_mitm::SourceProcess;
use tokio::net::{TcpListener, TcpStream};

use crate::ingress::{
    Ingress, IngressConnection, IngressError, IngressFactory, IngressRuntimeStatus, PlatformFlow,
    PlatformFlowMetadata, StartedIngress,
};

/// Windows redirected TCP endpoint requested at broker startup.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressEndpoint {
    listen_addr: SocketAddr,
}

impl IngressEndpoint {
    /// Creates a redirected TCP endpoint.
    #[must_use]
    pub const fn redirected_tcp(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    /// Returns a compact endpoint label for diagnostics.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.listen_addr.to_string()
    }

    /// Converts the endpoint into its concrete ingress factory.
    #[must_use]
    pub const fn into_factory(self) -> RedirectedTcpIngressFactory {
        RedirectedTcpIngressFactory::new(self.listen_addr)
    }
}

/// Factory for loopback TCP ingress used by Windows connect redirection.
pub struct RedirectedTcpIngressFactory {
    listen_addr: SocketAddr,
}

impl RedirectedTcpIngressFactory {
    /// Creates a loopback TCP ingress factory.
    #[must_use]
    pub const fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }
}

impl IngressFactory for RedirectedTcpIngressFactory {
    type Ingress = RedirectedTcpIngress;

    async fn start(self) -> Result<StartedIngress<Self::Ingress>, IngressError> {
        let ingress = RedirectedTcpIngress::bind(self.listen_addr).await?;
        let status = IngressRuntimeStatus::windows_wfp(ingress.listen_addr());
        Ok(StartedIngress::new(ingress, status))
    }
}

/// TCP listener targeted by the Windows WFP callout driver.
pub struct RedirectedTcpIngress {
    listener: TcpListener,
    listen_addr: SocketAddr,
}

impl RedirectedTcpIngress {
    /// Binds the loopback TCP ingress.
    ///
    /// # Errors
    ///
    /// Returns an error when binding fails or the concrete listener address
    /// cannot be read.
    pub async fn bind(listen_addr: SocketAddr) -> Result<Self, IngressError> {
        let listener = TcpListener::bind(listen_addr)
            .await
            .map_err(|source| IngressError::bind(listen_addr, source))?;
        let listen_addr = listener
            .local_addr()
            .map_err(IngressError::listener_address)?;

        Ok(Self {
            listener,
            listen_addr,
        })
    }

    /// Returns the concrete loopback TCP listener address.
    #[must_use]
    pub const fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

/// Accepted Windows socket awaiting redirect-context recovery.
pub struct RedirectedTcpConnection {
    stream: TcpStream,
    peer_addr: SocketAddr,
}

impl RedirectedTcpConnection {
    fn accepted_local_addr(
        stream: &TcpStream,
        peer_addr: SocketAddr,
    ) -> Result<SocketAddr, IngressError> {
        stream
            .local_addr()
            .map_err(|source| IngressError::local_address(peer_addr, source))
    }

    fn query_redirect_metadata(
        stream: &TcpStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<
        (
            crate::connection::OriginalDestination,
            Option<abyss_mitm::SourceProcess>,
        ),
        IngressError,
    > {
        let (original_destination, process_id, application_id) =
            crate::sys::query_redirect_metadata(stream)
                .map_err(|source| IngressError::redirect_context(peer_addr, local_addr, source))?;
        let source_process = Self::source_process(process_id, application_id);

        Ok((original_destination, source_process))
    }

    fn source_process(
        process_id: Option<u32>,
        application_id: Option<String>,
    ) -> Option<SourceProcess> {
        let process_name = application_id
            .as_deref()
            .and_then(Self::application_file_name)
            .map(str::to_owned);
        (process_id.is_some() || application_id.is_some()).then(|| {
            SourceProcess::new(process_id, process_name, None).with_application_id(application_id)
        })
    }

    fn application_file_name(application_id: &str) -> Option<&str> {
        application_id
            .rsplit(['\\', '/'])
            .find(|component| !component.is_empty())
    }
}

impl Ingress for RedirectedTcpIngress {
    type Accepted = RedirectedTcpConnection;

    async fn accept(&mut self) -> Result<Self::Accepted, IngressError> {
        let (stream, peer_addr) = self.listener.accept().await.map_err(IngressError::accept)?;

        Ok(RedirectedTcpConnection { stream, peer_addr })
    }
}

impl IngressConnection for RedirectedTcpConnection {
    async fn into_flow(self) -> Result<PlatformFlow, IngressError> {
        let Self { stream, peer_addr } = self;
        let local_addr = Self::accepted_local_addr(&stream, peer_addr)?;
        let (stream, redirect_metadata) = tokio::task::spawn_blocking(move || {
            let redirect_metadata = Self::query_redirect_metadata(&stream, peer_addr, local_addr);
            (stream, redirect_metadata)
        })
        .await
        .map_err(|source| IngressError::task("query Windows redirect context", source))?;
        let (original_destination, source_process) = redirect_metadata?;

        tracing::info!(
            %peer_addr,
            %local_addr,
            %original_destination,
            source_pid = ?source_process.as_ref().and_then(|source| source.pid),
            source_process = ?source_process.as_ref().and_then(|source| source.name.as_deref()),
            source_application_id = ?source_process
                .as_ref()
                .and_then(|source| source.application_id.as_deref()),
            "broker ingress accepted redirected TCP flow"
        );
        Ok(PlatformFlow::new(
            stream,
            PlatformFlowMetadata::from_parts(
                Some(peer_addr),
                Some(local_addr),
                original_destination,
                None,
                source_process,
            ),
        )
        .with_ingress(abyss_mitm::FlowIngress::transparent(
            abyss_mitm::TransparentFlowSource::WindowsWfp,
        )))
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpStream;

    use super::{
        Ingress as _, IngressConnection as _, IngressError, IngressFactory as _,
        RedirectedTcpConnection, RedirectedTcpIngress, RedirectedTcpIngressFactory,
    };

    #[test]
    fn source_process_uses_the_windows_application_filename() {
        let application_id = r"\device\harddiskvolume4\program files\openai\codex.exe";

        let source_process =
            RedirectedTcpConnection::source_process(Some(17_042), Some(application_id.to_owned()))
                .expect("platform source metadata should produce a source process");

        assert_eq!(source_process.pid, Some(17_042));
        assert_eq!(source_process.name.as_deref(), Some("codex.exe"));
        assert_eq!(
            source_process.application_id.as_deref(),
            Some(application_id)
        );
    }

    #[tokio::test]
    async fn factory_reports_loopback_tcp_status() {
        let started = RedirectedTcpIngressFactory::new(
            "127.0.0.1:0"
                .parse()
                .expect("loopback ingress address should parse"),
        )
        .start()
        .await
        .expect("test ingress should start");
        let (_ingress, status) = started.into_parts();

        let listen_addr = status
            .listen_addr()
            .expect("loopback TCP status should include a listener address");
        assert_ne!(
            listen_addr.port(),
            0,
            "factory should report the concrete bound TCP port"
        );
    }

    #[tokio::test]
    async fn plain_loopback_connection_without_redirect_metadata_is_rejected() {
        let mut ingress = RedirectedTcpIngress::bind(
            "127.0.0.1:0"
                .parse()
                .expect("loopback ingress address should parse"),
        )
        .await
        .expect("test ingress should bind");
        let listen_addr = ingress.listen_addr();

        let accept_task = tokio::spawn(async move {
            let accepted = ingress.accept().await?;
            accepted.into_flow().await
        });
        let client = TcpStream::connect(listen_addr)
            .await
            .expect("test client should connect");
        let accepted = accept_task.await.expect("accept task should join");
        let Err(error) = accepted else {
            panic!("plain loopback connection should not become a platform flow");
        };

        assert!(
            matches!(error, IngressError::RedirectContext { .. }),
            "connection without platform redirect metadata should be rejected, got {error}"
        );
        drop(client);
    }
}
