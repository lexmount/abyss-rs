//! Unix socket ingress for framed platform flow IPC.
//!
//! macOS Network Extension flows arrive as one Unix socket connection per TCP
//! flow. This module accepts the socket, validates the initial `FlowOpen` frame,
//! and exposes following `FlowData` frames as ordinary duplex byte IO.

mod framed_protocol;

pub(super) use framed_protocol::FlowProtocolError;

use std::{
    cmp,
    fs::Permissions,
    io,
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    pin::Pin,
    task::{Context, Poll},
};

use tokio::{
    fs,
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{UnixListener, UnixStream},
};
use uuid::Uuid;

use crate::process_context::{
    ProcessContextResolver, SharedProcessContextResolver, default_process_context_resolver,
};

use self::framed_protocol::{
    FRAME_HEADER_LEN, FlowClosePayload, FlowFrame, FlowFrameCodec, FlowFrameDirection,
    FlowFrameType, FlowOpenPayload, FlowTransportProtocol,
};
use super::{
    Ingress, IngressConnection, IngressError, IngressFactory, IngressRuntimeStatus, PlatformFlow,
    PlatformFlowMetadata, StartedIngress,
};

const WRITE_FRAME_PAYLOAD_CAP: usize = 64 * 1024;
const SOCKET_DIRECTORY_MODE: u32 = 0o2710;
const SOCKET_FILE_MODE: u32 = 0o660;

/// macOS framed Unix socket endpoint requested at broker startup.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressEndpoint {
    socket_path: PathBuf,
}

impl IngressEndpoint {
    /// Creates a framed Unix socket endpoint.
    #[must_use]
    pub const fn framed_unix(socket_path: PathBuf) -> Self {
        Self { socket_path }
    }

    /// Returns a compact endpoint label for diagnostics.
    #[must_use]
    pub fn endpoint_label(&self) -> String {
        self.socket_path.display().to_string()
    }

    /// Converts the endpoint into its concrete ingress factory.
    #[must_use]
    pub fn into_factory(self) -> FramedUnixIngressFactory {
        FramedUnixIngressFactory::new(self.socket_path)
    }
}

/// Factory for framed Unix socket ingress.
pub struct FramedUnixIngressFactory {
    socket_path: PathBuf,
    process_context_resolver: SharedProcessContextResolver,
}

impl FramedUnixIngressFactory {
    /// Creates a framed Unix socket ingress factory.
    #[must_use]
    pub fn new(socket_path: PathBuf) -> Self {
        Self {
            socket_path,
            process_context_resolver: default_process_context_resolver(),
        }
    }
}

impl IngressFactory for FramedUnixIngressFactory {
    type Ingress = FramedUnixIngress;

    async fn start(self) -> Result<StartedIngress<Self::Ingress>, IngressError> {
        let ingress =
            FramedUnixIngress::bind_with_resolver(self.socket_path, self.process_context_resolver)
                .await?;
        let status =
            IngressRuntimeStatus::macos_network_extension(ingress.socket_path().to_path_buf());
        Ok(StartedIngress::new(ingress, status))
    }
}

/// Unix socket listener accepting framed platform flows.
pub struct FramedUnixIngress {
    listener: UnixListener,
    socket_path: PathBuf,
    process_context_resolver: SharedProcessContextResolver,
}

impl FramedUnixIngress {
    async fn bind_with_resolver(
        socket_path: PathBuf,
        process_context_resolver: SharedProcessContextResolver,
    ) -> Result<Self, IngressError> {
        Self::create_parent_directory(&socket_path).await?;
        let listener = Self::bind_listener(&socket_path).await?;
        let ingress = Self {
            listener,
            socket_path,
            process_context_resolver,
        };
        Self::configure_socket_permissions(&ingress.socket_path).await?;
        Ok(ingress)
    }

    /// Returns the concrete Unix socket path.
    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    async fn create_parent_directory(socket_path: &Path) -> Result<(), IngressError> {
        if let Some(parent) = socket_path.parent()
            && !parent.as_os_str().is_empty()
        {
            let parent_existed = fs::try_exists(parent).await.map_err(|source| {
                IngressError::create_socket_directory(parent.to_path_buf(), source)
            })?;
            fs::create_dir_all(parent).await.map_err(|source| {
                IngressError::create_socket_directory(parent.to_path_buf(), source)
            })?;
            if !parent_existed || parent.file_name().is_some_and(|name| name == "abyss") {
                Self::configure_socket_directory_permissions(parent).await?;
            }
        }
        Ok(())
    }

    async fn bind_listener(socket_path: &Path) -> Result<UnixListener, IngressError> {
        let bind_error = match UnixListener::bind(socket_path) {
            Ok(listener) => return Ok(listener),
            Err(source) if source.kind() == io::ErrorKind::AddrInUse => source,
            Err(source) => {
                return Err(IngressError::bind_unix_socket(
                    socket_path.to_path_buf(),
                    source,
                ));
            }
        };

        // A Unix listener leaves its filesystem entry behind when the process
        // exits without an orderly shutdown. Probe before unlinking so an
        // active socket discovered here remains owned by the running broker.
        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                drop(stream);
                Err(IngressError::bind_unix_socket(
                    socket_path.to_path_buf(),
                    bind_error,
                ))
            }
            Err(source) if source.kind() == io::ErrorKind::ConnectionRefused => {
                if let Err(source) = fs::remove_file(socket_path).await
                    && source.kind() != io::ErrorKind::NotFound
                {
                    return Err(IngressError::remove_stale_unix_socket(
                        socket_path.to_path_buf(),
                        source,
                    ));
                }
                UnixListener::bind(socket_path).map_err(|source| {
                    IngressError::bind_unix_socket(socket_path.to_path_buf(), source)
                })
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                UnixListener::bind(socket_path).map_err(|source| {
                    IngressError::bind_unix_socket(socket_path.to_path_buf(), source)
                })
            }
            Err(_source) => Err(IngressError::bind_unix_socket(
                socket_path.to_path_buf(),
                bind_error,
            )),
        }
    }

    async fn configure_socket_directory_permissions(
        socket_directory: &Path,
    ) -> Result<(), IngressError> {
        fs::set_permissions(
            socket_directory,
            Permissions::from_mode(SOCKET_DIRECTORY_MODE),
        )
        .await
        .map_err(|source| {
            IngressError::configure_unix_socket_permissions(socket_directory.to_path_buf(), source)
        })
    }

    async fn configure_socket_permissions(socket_path: &Path) -> Result<(), IngressError> {
        // The installer assigns the parent directory to a shared group for the
        // Network Extension. The socket itself must not be world-accessible.
        fs::set_permissions(socket_path, Permissions::from_mode(SOCKET_FILE_MODE))
            .await
            .map_err(|source| {
                IngressError::configure_unix_socket_permissions(socket_path.to_path_buf(), source)
            })
    }

    async fn accept_stream(&self) -> Result<UnixStream, IngressError> {
        let (stream, _addr) =
            self.listener.accept().await.map_err(|source| {
                IngressError::accept_unix_socket(self.socket_path.clone(), source)
            })?;
        Ok(stream)
    }

    async fn read_open_frame(
        stream: &mut UnixStream,
    ) -> Result<(Uuid, FlowOpenPayload), IngressError> {
        let frame = FlowFrameCodec::read_frame(stream)
            .await
            .map_err(|source| IngressError::framed_protocol("read FlowOpen", source))?
            .ok_or(IngressError::invalid_framed_flow(
                "connection closed before FlowOpen",
            ))?;
        if frame.frame_type() != FlowFrameType::Open
            || frame.direction() != FlowFrameDirection::None
        {
            return Err(IngressError::invalid_framed_flow(
                "first frame must be FlowOpen",
            ));
        }

        let payload = FlowOpenPayload::decode(&frame)
            .map_err(|source| IngressError::framed_protocol("decode FlowOpen", source))?;
        if payload.flow_id != frame.flow_id() {
            return Err(IngressError::invalid_framed_flow(
                "FlowOpen payload flow_id does not match frame header",
            ));
        }
        if payload.protocol_name != FlowTransportProtocol::Tcp {
            return Err(IngressError::invalid_framed_flow(
                "only TCP framed flows are supported",
            ));
        }
        Ok((frame.flow_id(), payload))
    }

    async fn metadata_from_open(
        payload: FlowOpenPayload,
        process_context_resolver: SharedProcessContextResolver,
    ) -> Result<PlatformFlowMetadata, IngressError> {
        tracing::debug!(
            flow_id = %payload.flow_id,
            platform = %payload.platform.as_str(),
            source_pid = ?payload.source_pid,
            source_process = ?payload.source_process.as_deref(),
            source_application_id = ?payload.source_application_id.as_deref(),
            destination_host = ?payload.destination_host.as_deref(),
            destination_ip = ?payload.destination_ip,
            destination_port = ?payload.destination_port,
            original_tls_sni = ?payload.original_tls_sni.as_deref(),
            "broker ingress received framed FlowOpen metadata"
        );
        let destination = FramedFlowDestination::from_open(&payload).await?;
        let destination_host = payload
            .destination_host
            .clone()
            .filter(|host| !host.is_empty());
        let flow_id = abyss_mitm::FlowId::from(payload.flow_id);
        let source_process = tokio::task::spawn_blocking(move || {
            SourceProcessBuilder::from_open(&payload).build(process_context_resolver.as_ref())
        })
        .await
        .map_err(|source| IngressError::task("resolve source process context", source))?;
        Ok(PlatformFlowMetadata::from_parts(
            None,
            None,
            destination.original_destination,
            destination_host,
            source_process,
        )
        .with_flow_id(flow_id))
    }

    async fn remove_socket_file(socket_path: &Path) {
        if let Err(error) = fs::remove_file(socket_path).await
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %socket_path.display(),
                %error,
                "failed to remove framed ingress socket"
            );
        }
    }

    fn remove_socket_file_on_drop(socket_path: &Path) {
        if let Err(error) = std::fs::remove_file(socket_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(
                path = %socket_path.display(),
                %error,
                "failed to remove dropped framed ingress socket"
            );
        }
    }
}

impl Drop for FramedUnixIngress {
    fn drop(&mut self) {
        // An asynchronous destructor is not available. Normal shutdown awaits
        // Tokio removal first; direct drops and cancelled shutdown futures
        // unlink synchronously so they cannot leak the socket.
        Self::remove_socket_file_on_drop(&self.socket_path);
    }
}

impl Ingress for FramedUnixIngress {
    type Accepted = FramedUnixConnection;

    async fn accept(&mut self) -> Result<Self::Accepted, IngressError> {
        let stream = self.accept_stream().await?;
        Ok(FramedUnixConnection {
            stream,
            socket_path: self.socket_path.clone(),
            process_context_resolver: self.process_context_resolver.clone(),
        })
    }

    async fn shutdown(self) {
        Self::remove_socket_file(&self.socket_path).await;
    }
}

/// Accepted framed Unix connection awaiting its initial `FlowOpen`.
pub struct FramedUnixConnection {
    stream: UnixStream,
    socket_path: PathBuf,
    process_context_resolver: SharedProcessContextResolver,
}

impl IngressConnection for FramedUnixConnection {
    async fn into_flow(self) -> Result<PlatformFlow, IngressError> {
        let Self {
            mut stream,
            socket_path,
            process_context_resolver,
        } = self;
        let (flow_id, payload) = FramedUnixIngress::read_open_frame(&mut stream).await?;
        let metadata =
            FramedUnixIngress::metadata_from_open(payload, process_context_resolver).await?;

        tracing::info!(
            %flow_id,
            socket_path = %socket_path.display(),
            original_destination = %metadata.original_destination(),
            destination_host = ?metadata.destination_host(),
            fake_ip_candidate = metadata.original_destination().special_address_range().is_some(),
            "broker ingress accepted framed Unix flow"
        );
        Ok(
            PlatformFlow::new(FramedFlowIo::new(stream, flow_id), metadata).with_ingress(
                abyss_mitm::FlowIngress::transparent(
                    abyss_mitm::TransparentFlowSource::MacosNetworkExtension,
                ),
            ),
        )
    }
}

struct FramedFlowDestination {
    original_destination: crate::connection::OriginalDestination,
}

impl FramedFlowDestination {
    async fn from_open(payload: &FlowOpenPayload) -> Result<Self, IngressError> {
        let port = payload
            .destination_port
            .ok_or(IngressError::invalid_framed_flow(
                "FlowOpen missing destination_port",
            ))?;
        if let Some(ip) = payload.destination_ip {
            return Ok(Self {
                original_destination: SocketAddr::new(ip, port).into(),
            });
        }
        let host = payload
            .destination_host
            .as_ref()
            .filter(|host| !host.is_empty())
            .ok_or(IngressError::invalid_framed_flow(
                "FlowOpen missing destination_ip and destination_host",
            ))?;
        let mut addresses = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|source| IngressError::resolve_destination(host.clone(), port, source))?;
        let destination = addresses.next().ok_or(IngressError::invalid_framed_flow(
            "destination_host resolved to no addresses",
        ))?;
        Ok(Self {
            original_destination: destination.into(),
        })
    }
}

struct SourceProcessBuilder<'a> {
    payload: &'a FlowOpenPayload,
}

impl<'a> SourceProcessBuilder<'a> {
    const fn from_open(payload: &'a FlowOpenPayload) -> Self {
        Self { payload }
    }

    fn build(
        &self,
        process_context_resolver: &dyn ProcessContextResolver,
    ) -> Option<abyss_mitm::SourceProcess> {
        if self.payload.source_pid.is_none()
            && self.payload.source_process.is_none()
            && self.payload.source_application_id.is_none()
        {
            return None;
        }
        let executable_path = self.payload.source_process.clone();
        let name = executable_path
            .as_deref()
            .and_then(|path| Path::new(path).file_name())
            .and_then(|name| name.to_str())
            .map(str::to_owned);
        Some(
            abyss_mitm::SourceProcess::new(self.payload.source_pid, name, executable_path)
                .with_pid_version(self.payload.source_pid_version)
                .with_application_id(self.payload.source_application_id.clone())
                .with_working_directory(
                    process_context_resolver
                        .working_directory(self.payload.source_pid, self.payload.source_pid_version)
                        .map(|path| path.to_string_lossy().into_owned()),
                ),
        )
    }
}

struct FramedFlowIo {
    stream: UnixStream,
    flow_id: Uuid,
    read_state: FrameReadState,
    write_state: FrameWriteState,
    client_input_closed: bool,
}

impl FramedFlowIo {
    const fn new(stream: UnixStream, flow_id: Uuid) -> Self {
        Self {
            stream,
            flow_id,
            read_state: FrameReadState::new(),
            write_state: FrameWriteState::new(),
            client_input_closed: false,
        }
    }

    fn poll_next_client_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<Option<Vec<u8>>>> {
        let this = self.get_mut();
        if this.client_input_closed {
            return Poll::Ready(Ok(None));
        }
        let frame = match this.read_state.poll_next_frame(&mut this.stream, context)? {
            Poll::Ready(Some(frame)) => frame,
            Poll::Ready(None) => {
                this.client_input_closed = true;
                tracing::debug!(
                    flow_id = %this.flow_id,
                    reason = "socket_eof",
                    "framed flow client input closed without FlowClose"
                );
                return Poll::Ready(Ok(None));
            }
            Poll::Pending => return Poll::Pending,
        };
        if frame.flow_id() != this.flow_id {
            return Poll::Ready(Err(invalid_data("framed flow_id mismatch")));
        }
        match (frame.frame_type(), frame.direction()) {
            (FlowFrameType::Data, FlowFrameDirection::ClientToBroker) => {
                Poll::Ready(Ok(Some(frame.into_payload())))
            }
            (FlowFrameType::Close, FlowFrameDirection::ClientToBroker) => {
                let close = FlowClosePayload::decode(&frame).map_err(io_error)?;
                if close.flow_id != this.flow_id {
                    return Poll::Ready(Err(invalid_data(
                        "FlowClose payload flow_id does not match frame header",
                    )));
                }
                this.client_input_closed = true;
                tracing::debug!(
                    flow_id = %this.flow_id,
                    reason = %close.reason,
                    "framed flow client input closed"
                );
                Poll::Ready(Ok(None))
            }
            _ => Poll::Ready(Err(invalid_data("unexpected framed flow frame"))),
        }
    }
}

impl AsyncRead for FramedFlowIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.read_state.copy_ready_payload(buffer) {
                return Poll::Ready(Ok(()));
            }
            if buffer.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            match self.as_mut().poll_next_client_frame(context)? {
                Poll::Ready(Some(payload)) => {
                    self.read_state.set_ready_payload(payload);
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for FramedFlowIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buffer.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.as_mut().get_mut();
        if !this.write_state.has_pending_frame() {
            let payload_len = cmp::min(buffer.len(), WRITE_FRAME_PAYLOAD_CAP);
            let frame = FlowFrame::broker_to_client(this.flow_id, buffer[..payload_len].to_vec());
            this.write_state.queue_frame(&frame, payload_len)?;
        }
        match this.write_state.poll_drain(&mut this.stream, context)? {
            Poll::Ready(()) => Poll::Ready(Ok(this.write_state.take_completed_len())),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        match this.write_state.poll_drain(&mut this.stream, context)? {
            Poll::Ready(()) => Pin::new(&mut this.stream).poll_flush(context),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.as_mut().get_mut();
        if !this.write_state.shutdown_queued() {
            // The macOS Network Extension reads broker output as FlowFrame
            // records. Queue an explicit close record before shutting down the
            // underlying Unix stream so the Swift decoder observes a complete
            // protocol close instead of an EOF in the middle of a frame.
            let close =
                FlowFrame::broker_to_client_eof(this.flow_id, "core_shutdown").map_err(io_error)?;
            this.write_state.queue_frame(&close, 0)?;
            this.write_state.mark_shutdown_queued();
        }
        match this.write_state.poll_drain(&mut this.stream, context)? {
            Poll::Ready(()) => Pin::new(&mut this.stream).poll_shutdown(context),
            Poll::Pending => Poll::Pending,
        }
    }
}

struct FrameReadState {
    header: [u8; FRAME_HEADER_LEN],
    header_len: usize,
    payload: Vec<u8>,
    payload_len: Option<usize>,
    payload_offset: usize,
    ready_payload: Vec<u8>,
    ready_payload_offset: usize,
}

impl FrameReadState {
    const fn new() -> Self {
        Self {
            header: [0; FRAME_HEADER_LEN],
            header_len: 0,
            payload: Vec::new(),
            payload_len: None,
            payload_offset: 0,
            ready_payload: Vec::new(),
            ready_payload_offset: 0,
        }
    }

    fn set_ready_payload(&mut self, payload: Vec<u8>) {
        self.ready_payload = payload;
        self.ready_payload_offset = 0;
    }

    fn copy_ready_payload(&mut self, buffer: &mut ReadBuf<'_>) -> bool {
        if self.ready_payload_offset >= self.ready_payload.len() {
            self.ready_payload.clear();
            self.ready_payload_offset = 0;
            return false;
        }
        let remaining = &self.ready_payload[self.ready_payload_offset..];
        let copy_len = cmp::min(remaining.len(), buffer.remaining());
        buffer.put_slice(&remaining[..copy_len]);
        self.ready_payload_offset = self
            .ready_payload_offset
            .checked_add(copy_len)
            .expect("ready payload copy length is bounded by remaining payload");
        true
    }

    fn poll_next_frame(
        &mut self,
        stream: &mut UnixStream,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<Option<FlowFrame>>> {
        while self.header_len < FRAME_HEADER_LEN {
            match self.poll_read_header(stream, context)? {
                Poll::Ready(Some(())) => {}
                Poll::Ready(None) => return Poll::Ready(Ok(None)),
                Poll::Pending => return Poll::Pending,
            }
        }
        if self.payload_len.is_none() {
            let payload_len = FlowFrame::payload_len(&self.header).map_err(io_error)?;
            let payload_len = usize::try_from(payload_len)
                .map_err(|_error| invalid_data("frame payload length does not fit usize"))?;
            self.payload = vec![0; payload_len];
            self.payload_len = Some(payload_len);
            self.payload_offset = 0;
        }
        match self.poll_read_payload(stream, context)? {
            Poll::Ready(()) => {
                let payload = std::mem::take(&mut self.payload);
                let frame = FlowFrame::decode(&self.header, payload).map_err(io_error)?;
                self.reset_frame();
                Poll::Ready(Ok(Some(frame)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_read_header(
        &mut self,
        stream: &mut UnixStream,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<Option<()>>> {
        let mut read_buffer = ReadBuf::new(&mut self.header[self.header_len..]);
        match Pin::new(stream).poll_read(context, &mut read_buffer)? {
            Poll::Ready(()) => {
                let read_len = read_buffer.filled().len();
                if read_len == 0 {
                    if self.header_len == 0 {
                        return Poll::Ready(Ok(None));
                    }
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF while reading frame header",
                    )));
                }
                self.header_len = self
                    .header_len
                    .checked_add(read_len)
                    .ok_or_else(|| invalid_data("frame header offset overflow"))?;
                Poll::Ready(Ok(Some(())))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_read_payload(
        &mut self,
        stream: &mut UnixStream,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let payload_len = self
            .payload_len
            .expect("payload length is set before reading payload");
        while self.payload_offset < payload_len {
            let mut read_buffer = ReadBuf::new(&mut self.payload[self.payload_offset..]);
            match Pin::new(&mut *stream).poll_read(context, &mut read_buffer)? {
                Poll::Ready(()) => {
                    let read_len = read_buffer.filled().len();
                    if read_len == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "EOF while reading frame payload",
                        )));
                    }
                    self.payload_offset = self
                        .payload_offset
                        .checked_add(read_len)
                        .ok_or_else(|| invalid_data("frame payload offset overflow"))?;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    const fn reset_frame(&mut self) {
        self.header = [0; FRAME_HEADER_LEN];
        self.header_len = 0;
        self.payload_len = None;
        self.payload_offset = 0;
    }
}

struct FrameWriteState {
    frame: Vec<u8>,
    offset: usize,
    consumed_len: usize,
    completed_len: usize,
    shutdown_queued: bool,
}

impl FrameWriteState {
    const fn new() -> Self {
        Self {
            frame: Vec::new(),
            offset: 0,
            consumed_len: 0,
            completed_len: 0,
            shutdown_queued: false,
        }
    }

    const fn has_pending_frame(&self) -> bool {
        !self.frame.is_empty()
    }

    const fn shutdown_queued(&self) -> bool {
        self.shutdown_queued
    }

    const fn mark_shutdown_queued(&mut self) {
        self.shutdown_queued = true;
    }

    fn queue_frame(&mut self, frame: &FlowFrame, consumed_len: usize) -> io::Result<()> {
        if self.has_pending_frame() {
            return Err(invalid_data("write frame already pending"));
        }
        self.frame = frame.encode().map_err(io_error)?;
        self.offset = 0;
        self.consumed_len = consumed_len;
        self.completed_len = 0;
        Ok(())
    }

    fn poll_drain(
        &mut self,
        stream: &mut UnixStream,
        context: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        while self.offset < self.frame.len() {
            match Pin::new(&mut *stream).poll_write(context, &self.frame[self.offset..])? {
                Poll::Ready(0) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write framed flow bytes",
                    )));
                }
                Poll::Ready(write_len) => {
                    self.offset = self
                        .offset
                        .checked_add(write_len)
                        .ok_or_else(|| invalid_data("frame write offset overflow"))?;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        if !self.frame.is_empty() {
            self.frame.clear();
            self.offset = 0;
            self.completed_len = self.consumed_len;
            self.consumed_len = 0;
        }
        Poll::Ready(Ok(()))
    }

    const fn take_completed_len(&mut self) -> usize {
        let completed_len = self.completed_len;
        self.completed_len = 0;
        completed_len
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn io_error<E>(error: E) -> io::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, sync::Arc};

    use tokio::{
        fs,
        io::{AsyncReadExt as _, AsyncWriteExt as _},
    };

    use super::framed_protocol::{
        FlowFrame, FlowFrameCodec, FlowFrameDirection, FlowFrameType, FlowOpenPayload,
        FlowTransportProtocol,
    };
    use super::{
        FramedFlowIo, FramedUnixIngress, FramedUnixIngressFactory, SOCKET_FILE_MODE,
        SourceProcessBuilder,
    };
    use crate::ingress::{Ingress as _, IngressConnection as _, IngressError, IngressFactory as _};
    use crate::process_context::ProcessContextResolver;

    struct FixedProcessContextResolver {
        working_directory: PathBuf,
    }

    impl ProcessContextResolver for FixedProcessContextResolver {
        fn working_directory(
            &self,
            _pid: Option<u32>,
            _pid_version: Option<u32>,
        ) -> Option<PathBuf> {
            Some(self.working_directory.clone())
        }
    }

    struct UnavailableProcessContextResolver;

    impl ProcessContextResolver for UnavailableProcessContextResolver {
        fn working_directory(
            &self,
            _pid: Option<u32>,
            _pid_version: Option<u32>,
        ) -> Option<PathBuf> {
            None
        }
    }

    #[test]
    fn source_process_builder_retains_application_identity_without_pid_or_path() {
        let payload = FlowOpenPayload {
            flow_id: uuid::Uuid::new_v4(),
            platform: "macos".to_owned(),
            protocol_name: FlowTransportProtocol::Tcp,
            source_pid: None,
            source_pid_version: None,
            source_process: None,
            source_application_id: Some("com.openai.codex".to_owned()),
            destination_host: Some("api.openai.com".to_owned()),
            destination_ip: None,
            destination_port: Some(443),
            original_tls_sni: None,
        };

        let source_process = SourceProcessBuilder::from_open(&payload)
            .build(&UnavailableProcessContextResolver)
            .expect("application identity alone should retain source metadata");

        assert_eq!(source_process.pid, None);
        assert_eq!(source_process.name, None);
        assert_eq!(source_process.executable_path, None);
        assert_eq!(
            source_process.application_id.as_deref(),
            Some("com.openai.codex")
        );
    }

    #[tokio::test]
    async fn framed_flow_io_reads_client_data_and_writes_broker_data() {
        let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let (client, mut broker_peer) =
            tokio::net::UnixStream::pair().expect("test UnixStream pair should create");
        let mut io = FramedFlowIo::new(client, flow_id);

        let client_frame = FlowFrame::new(
            FlowFrameType::Data,
            FlowFrameDirection::ClientToBroker,
            flow_id,
            b"GET / HTTP/1.1\r\n".to_vec(),
        );
        FlowFrameCodec::write_frame(&mut broker_peer, &client_frame)
            .await
            .expect("client data frame should write");

        let mut received = vec![0; 16];
        io.read_exact(&mut received)
            .await
            .expect("framed IO should expose client payload bytes");
        assert_eq!(received, b"GET / HTTP/1.1\r\n");

        io.write_all(b"HTTP/1.1 200 OK\r\n\r\n")
            .await
            .expect("framed IO should write broker payload bytes");
        let response_frame = FlowFrameCodec::read_frame(&mut broker_peer)
            .await
            .expect("response frame should read")
            .expect("response frame should exist");
        assert_eq!(response_frame.frame_type(), FlowFrameType::Data);
        assert_eq!(
            response_frame.direction(),
            FlowFrameDirection::BrokerToClient
        );
        assert_eq!(response_frame.flow_id(), flow_id);
        assert_eq!(response_frame.payload(), b"HTTP/1.1 200 OK\r\n\r\n");
    }

    #[tokio::test]
    async fn framed_flow_io_shutdown_sends_complete_close_frame() {
        // Regression coverage for HTTP flows that finish immediately after a
        // response body. The MITM relay calls `shutdown()` after forwarding the
        // response; the macOS bridge must receive the response bytes and then a
        // FlowClose frame, not a bare socket EOF.
        let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let (client, mut broker_peer) =
            tokio::net::UnixStream::pair().expect("test UnixStream pair should create");
        let mut io = FramedFlowIo::new(client, flow_id);

        io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .expect("framed IO should write response data");
        io.shutdown()
            .await
            .expect("framed IO should write a close frame before shutdown");

        let response_frame = FlowFrameCodec::read_frame(&mut broker_peer)
            .await
            .expect("response frame should read")
            .expect("response frame should exist");
        assert_eq!(response_frame.frame_type(), FlowFrameType::Data);
        assert_eq!(
            response_frame.direction(),
            FlowFrameDirection::BrokerToClient
        );
        assert_eq!(
            response_frame.payload(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
        );

        // The close frame must be a real framed protocol message. If this were
        // replaced by a socket-level EOF, the Swift bridge could report
        // `unexpectedEOF` and terminate the intercepted client stream.
        let close_frame = FlowFrameCodec::read_frame(&mut broker_peer)
            .await
            .expect("close frame should read")
            .expect("close frame should exist");
        assert_eq!(close_frame.frame_type(), FlowFrameType::Close);
        assert_eq!(close_frame.direction(), FlowFrameDirection::BrokerToClient);
        assert_eq!(close_frame.flow_id(), flow_id);
    }

    #[tokio::test]
    async fn ingress_accepts_flow_open_metadata() {
        let socket_path = std::env::temp_dir().join(format!(
            "abyss-framed-ingress-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let mut ingress = FramedUnixIngress::bind_with_resolver(
            socket_path.clone(),
            Arc::new(FixedProcessContextResolver {
                working_directory: PathBuf::from("/tmp/abyss-project"),
            }),
        )
        .await
        .expect("framed ingress should start");
        assert_eq!(ingress.socket_path(), socket_path.as_path());

        let flow_id = uuid::Uuid::from_u128(0x1234_5678_90ab_cdef_1234_5678_90ab_cdef);
        let accept_task = tokio::spawn(async move {
            let accepted = ingress.accept().await?;
            let flow = accepted.into_flow().await?;
            Ok::<_, IngressError>((flow, ingress))
        });
        let mut client = tokio::net::UnixStream::connect(&socket_path)
            .await
            .expect("client should connect to framed ingress");
        let payload = format!(
            r#"{{
                "flow_id": "{flow_id}",
                "platform": "macos",
                "protocol": "tcp",
                "source_pid": 123,
                "source_pid_version": 7,
                "source_process": "/usr/bin/curl",
                "source_application_id": "com.apple.curl",
                "destination_host": null,
                "destination_ip": "127.0.0.1",
                "destination_port": 443,
                "original_tls_sni": null
            }}"#
        );
        let open = FlowFrame::new(
            FlowFrameType::Open,
            FlowFrameDirection::None,
            flow_id,
            payload.into_bytes(),
        );
        FlowFrameCodec::write_frame(&mut client, &open)
            .await
            .expect("FlowOpen should write");

        let (flow, ingress) = accept_task
            .await
            .expect("accept task should join")
            .expect("FlowOpen should produce PlatformFlow");
        assert_eq!(
            flow.original_destination(),
            &crate::connection::OriginalDestination {
                ip: "127.0.0.1".parse().expect("test IP address should parse"),
                port: 443,
            }
        );
        assert_eq!(flow.peer_addr(), None);
        assert_eq!(flow.local_addr(), None);
        let source_process = flow
            .source_process()
            .expect("FlowOpen source process should be retained");
        assert_eq!(source_process.pid, Some(123));
        assert_eq!(source_process.pid_version, Some(7));
        assert_eq!(
            source_process.application_id.as_deref(),
            Some("com.apple.curl")
        );
        assert_eq!(
            source_process.working_directory.as_deref(),
            Some("/tmp/abyss-project")
        );
        assert_eq!(
            flow.into_mitm_flow().flow_id(),
            &abyss_mitm::FlowId::from(flow_id)
        );
        ingress.shutdown().await;
    }

    #[tokio::test]
    async fn ingress_rebinds_socket_left_by_an_unordered_shutdown() {
        let socket_path = std::env::temp_dir().join(format!(
            "abyss-framed-stale-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let stale_listener =
            tokio::net::UnixListener::bind(&socket_path).expect("stale test listener should bind");
        drop(stale_listener);
        assert!(
            fs::try_exists(&socket_path)
                .await
                .expect("stale socket path should be queryable"),
            "dropping a Unix listener should leave its socket path behind"
        );

        let ingress = FramedUnixIngress::bind_with_resolver(
            socket_path.clone(),
            Arc::new(FixedProcessContextResolver {
                working_directory: PathBuf::from("/tmp/abyss-project"),
            }),
        )
        .await
        .expect("framed ingress should replace a stale socket");
        assert_eq!(ingress.socket_path(), socket_path.as_path());

        ingress.shutdown().await;
        assert!(
            !fs::try_exists(socket_path)
                .await
                .expect("socket path should be queryable after shutdown"),
            "orderly shutdown should remove the replacement socket"
        );
    }

    #[tokio::test]
    async fn dropping_ingress_removes_socket_file() {
        let socket_path = std::env::temp_dir().join(format!(
            "abyss-framed-drop-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let ingress = FramedUnixIngress::bind_with_resolver(
            socket_path.clone(),
            Arc::new(FixedProcessContextResolver {
                working_directory: PathBuf::from("/tmp/abyss-project"),
            }),
        )
        .await
        .expect("framed ingress should start");
        assert!(
            fs::try_exists(&socket_path)
                .await
                .expect("socket path should be queryable before drop"),
            "bound ingress should create its socket file"
        );

        drop(ingress);

        assert!(
            !fs::try_exists(socket_path)
                .await
                .expect("socket path should be queryable after drop"),
            "dropping an ingress should remove its socket file"
        );
    }

    #[tokio::test]
    async fn ingress_sets_socket_permissions_for_platform_extension() {
        let socket_path = PathBuf::from(format!(
            "/tmp/abyss-fi-mode-{}-{}.sock",
            std::process::id(),
            rand::random::<u64>()
        ));
        let started = FramedUnixIngressFactory::new(socket_path.clone())
            .start()
            .await
            .expect("framed ingress should start");

        let mode = fs::metadata(&socket_path)
            .await
            .expect("framed ingress socket should exist")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SOCKET_FILE_MODE);

        let (ingress, _status) = started.into_parts();
        ingress.shutdown().await;
    }
}
