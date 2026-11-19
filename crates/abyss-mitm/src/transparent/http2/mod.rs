//! Multiplexed HTTP/2 relay. Connection drivers own framing; each stream owns its exchange.

use bytes::Bytes;
use futures_util::{FutureExt as _, StreamExt as _, stream::FuturesUnordered};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::io::{AsyncRead, AsyncWrite};

use super::{
    BoxedDuplexStream, FlowContext, FlowOperation, HttpExchange, MitmEngine, RedirectTarget,
    RequestForwardingControl, TransparentFlowError, relay::RelayOutcome,
};

pub(super) mod body;
mod io;
mod request;
mod stream;

const MAX_CONCURRENT_STREAMS: u32 = 32;

pub(super) struct Http2Relay<'a, C> {
    context: FlowContext,
    engine: &'a MitmEngine,
    control: &'a C,
    redirect: Option<&'a RedirectTarget>,
    request_connector: super::upstream::RequestConnector,
    observer: Option<Arc<dyn super::TrafficObserver>>,
}

impl<'a, C: RequestForwardingControl> Http2Relay<'a, C> {
    pub(super) const fn new(
        context: FlowContext,
        engine: &'a MitmEngine,
        control: &'a C,
        redirect: Option<&'a RedirectTarget>,
        request_connector: super::upstream::RequestConnector,
        observer: Option<Arc<dyn super::TrafficObserver>>,
    ) -> Self {
        Self {
            context,
            engine,
            control,
            redirect,
            request_connector,
            observer,
        }
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "Tokio select uses remainder internally for fair branch polling"
    )]
    pub(super) async fn relay<S: AsyncRead + AsyncWrite + Unpin>(
        self,
        client: S,
        upstream: BoxedDuplexStream,
    ) -> Result<RelayOutcome, TransparentFlowError> {
        let client_bytes = Arc::new(AtomicU64::new(0));
        // The flow's upstream byte total includes writes to the shared connection
        // and to any provider connections opened for individual streams.
        let upstream_bytes = Arc::new(AtomicU64::new(0));
        let handshake = h2::server::Builder::new()
            .max_concurrent_streams(MAX_CONCURRENT_STREAMS)
            .max_header_list_size(64 * 1024)
            .max_send_buffer_size(16 * 1024)
            .handshake::<_, Bytes>(io::CountedIo::new(client, client_bytes.clone()));
        let mut client = tokio::time::timeout(self.engine.timeouts.http1_request_head, handshake)
            .await
            .map_err(|_| TransparentFlowError::Timeout {
                operation: FlowOperation::ReadAgentRequestHead,
                timeout: self.engine.timeouts.http1_request_head,
            })?
            .map_err(error)?;
        let (sender, origin) = upstream_handshake(upstream, upstream_bytes.clone()).await?;
        tokio::pin!(origin);
        let pending = FuturesUnordered::new();
        tokio::pin!(pending);
        let mut first: Option<HttpExchange> = None;
        let mut origin_closed = false;
        let mut connection_error = None;
        let mut received_request = false;
        let first_request_timeout = tokio::time::sleep(self.engine.timeouts.http1_request_head);
        tokio::pin!(first_request_timeout);
        loop {
            tokio::select! {
                () = &mut first_request_timeout, if !received_request => {
                    return Err(TransparentFlowError::Timeout {
                        operation: FlowOperation::ReadAgentRequestHead,
                        timeout: self.engine.timeouts.http1_request_head,
                    });
                }
                result = &mut origin, if !origin_closed => {
                    origin_closed = true;
                    if let Err(error) = result {
                        tracing::debug!(%error, "HTTP/2 origin connection closed");
                    }
                    client.graceful_shutdown();
                }
                incoming = client.accept() => {
                    let Some(incoming) = incoming else { break; };
                    let (request, mut respond) = match incoming {
                        Ok(incoming) => incoming,
                        Err(failure) => {
                            connection_error = Some(error(failure));
                            break;
                        }
                    };
                    received_request = true;
                    if origin_closed || pending.len() >= usize::try_from(MAX_CONCURRENT_STREAMS).unwrap_or(32) {
                        respond.send_reset(h2::Reason::REFUSED_STREAM);
                    } else {
                        pending.push(self.exchange(request, respond, sender.clone(), upstream_bytes.clone()));
                    }
                }
                result = pending.next(), if !pending.is_empty() => {
                    if first.is_none() { first = result.flatten(); }
                }
            }
        }
        // accept() marks outstanding stream handles closed before returning. Give
        // ready captures one final poll to observe that closure and publish their
        // bounded prefixes; never wait for unfinished uploads or inspection work.
        while let Some(Some(result)) = pending.next().now_or_never() {
            if first.is_none() {
                first = result;
            }
        }
        // All stream handles belong to this connection and are dropped together
        // on disconnect. They cannot outlive policy/control references or leak tasks.
        let first = first.ok_or_else(|| {
            connection_error.unwrap_or(TransparentFlowError::ClientClosedBeforeProtocol)
        })?;
        Ok(RelayOutcome {
            protocol: self.context.protocol.clone(),
            first_request: first.request,
            first_response: first.response,
            client_to_upstream_bytes: upstream_bytes.load(Ordering::Relaxed),
            upstream_to_client_bytes: client_bytes.load(Ordering::Relaxed),
        })
    }
}

type UpstreamDriver = h2::client::Connection<io::CountedIo<BoxedDuplexStream>, Bytes>;

async fn upstream_handshake(
    stream: BoxedDuplexStream,
    written: Arc<AtomicU64>,
) -> Result<(h2::client::SendRequest<Bytes>, UpstreamDriver), TransparentFlowError> {
    h2::client::Builder::new()
        .enable_push(false)
        .max_header_list_size(64 * 1024)
        .max_send_buffer_size(16 * 1024)
        .handshake(io::CountedIo::new(stream, written))
        .await
        .map_err(error)
}

fn error(source: h2::Error) -> TransparentFlowError {
    TransparentFlowError::Io {
        operation: FlowOperation::LocalRelay,
        source: std::io::Error::other(source),
    }
}
