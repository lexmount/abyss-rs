//! Accepted transparent TCP flow wrapper.
//!
//! Platform ingress code hands the MITM pipeline duplex byte IO plus the
//! destination captured before interception changed the connection path. This
//! type keeps those pieces together as the flow enters protocol detection.

use std::{net::SocketAddr, sync::Arc};

use tokio::net::TcpStream;

use super::{
    BoxedDuplexStream, DuplexStream, FlowId, FlowIngress, OriginalDestination, SourceProcess,
    TrafficDirection, TrafficObserver, TransparentFlowSource,
    io::{ObservedStream, PrefixedDuplexStream},
};

/// How the MITM pipeline obtains the upstream TCP stream.
pub(super) enum UpstreamConnection {
    /// Connect to the normalized original destination inside the MITM pipeline.
    Deferred,
    /// Reuse a stream established while accepting an explicit proxy request.
    Prepared(TcpStream),
}

/// Accepted transparent flow plus metadata needed by MITM processing.
pub struct AcceptedTcpFlow {
    pub(super) flow_id: FlowId,
    pub(super) stream: BoxedDuplexStream,
    pub(super) peer_addr: Option<SocketAddr>,
    pub(super) local_addr: Option<SocketAddr>,
    pub(super) original_destination: OriginalDestination,
    pub(super) destination_host: Option<String>,
    pub(super) source_process: Option<SourceProcess>,
    pub(super) ingress: FlowIngress,
    pub(super) upstream: UpstreamConnection,
    pub(super) traffic_observer: Option<Arc<dyn TrafficObserver>>,
}

impl AcceptedTcpFlow {
    /// Creates a transparent flow from platform byte IO and metadata.
    #[must_use]
    pub fn new<S>(
        stream: S,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        original_destination: OriginalDestination,
    ) -> Self
    where
        S: DuplexStream + 'static,
    {
        Self::from_boxed_parts(
            Box::new(stream),
            Some(peer_addr),
            Some(local_addr),
            original_destination,
            None,
        )
    }

    /// Creates a transparent flow from boxed platform byte IO.
    #[must_use]
    pub fn from_boxed(
        stream: BoxedDuplexStream,
        peer_addr: SocketAddr,
        local_addr: SocketAddr,
        original_destination: OriginalDestination,
    ) -> Self {
        Self::from_boxed_parts(
            stream,
            Some(peer_addr),
            Some(local_addr),
            original_destination,
            None,
        )
    }

    /// Creates a transparent flow from boxed platform byte IO and normalized metadata.
    #[must_use]
    pub fn from_boxed_parts(
        stream: BoxedDuplexStream,
        peer_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        original_destination: OriginalDestination,
        source_process: Option<SourceProcess>,
    ) -> Self {
        Self {
            flow_id: FlowId::generate(),
            stream,
            peer_addr,
            local_addr,
            original_destination,
            destination_host: None,
            source_process,
            ingress: FlowIngress::transparent(TransparentFlowSource::Unattributed),
            upstream: UpstreamConnection::Deferred,
            traffic_observer: None,
        }
    }

    /// Replaces the generated identity with one supplied by a platform ingress.
    #[must_use]
    pub const fn with_flow_id(mut self, flow_id: FlowId) -> Self {
        self.flow_id = flow_id;
        self
    }

    /// Returns the stable identity of this accepted network flow.
    #[must_use]
    pub const fn flow_id(&self) -> &FlowId {
        &self.flow_id
    }

    /// Attaches the normalized ingress description used by hooks and diagnostics.
    #[must_use]
    pub fn with_ingress(mut self, ingress: FlowIngress) -> Self {
        self.ingress = ingress;
        self
    }

    /// Attaches a destination hostname recovered by a transparent adapter.
    #[must_use]
    pub fn with_destination_host(mut self, destination_host: Option<String>) -> Self {
        self.destination_host = destination_host;
        self
    }

    /// Attaches a metadata-only byte observer to this flow.
    #[must_use]
    pub fn with_traffic_observer(mut self, observer: Arc<dyn TrafficObserver>) -> Self {
        self.stream = Box::new(ObservedStream::new(
            self.stream,
            observer.clone(),
            TrafficDirection::ClientToUpstream,
        ));
        self.traffic_observer = Some(observer);
        self
    }

    pub(super) fn with_existing_traffic_observer(
        mut self,
        observer: Arc<dyn TrafficObserver>,
    ) -> Self {
        self.traffic_observer = Some(observer);
        self
    }

    /// Reuses an upstream TCP stream established by the ingress adapter.
    ///
    /// Explicit proxy ingress resolves and connects before acknowledging a
    /// `CONNECT` request, so the MITM pipeline must consume that exact stream
    /// rather than opening a second connection.
    #[must_use]
    pub fn with_prepared_upstream(mut self, upstream: TcpStream) -> Self {
        self.upstream = UpstreamConnection::Prepared(upstream);
        self
    }

    pub(super) fn with_upstream_connection(mut self, upstream: UpstreamConnection) -> Self {
        self.upstream = upstream;
        self
    }

    /// Replays already-read bytes before the remaining client stream.
    #[must_use]
    pub fn with_read_prefix(self, prefix: Box<[u8]>) -> Self {
        if prefix.is_empty() {
            return self;
        }

        Self {
            flow_id: self.flow_id,
            stream: PrefixedDuplexStream::new(prefix, self.stream).boxed(),
            peer_addr: self.peer_addr,
            local_addr: self.local_addr,
            original_destination: self.original_destination,
            destination_host: self.destination_host,
            source_process: self.source_process,
            ingress: self.ingress,
            upstream: self.upstream,
            traffic_observer: self.traffic_observer,
        }
    }
}
