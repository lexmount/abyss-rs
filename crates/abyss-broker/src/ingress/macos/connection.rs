//! Prepares opt-in direct TCP connections before the native adapter opens its flow.
//!
//! Configured proxies remain deferred because their logical target may require
//! `ClientHello` SNI or HTTP Host bytes. Legacy adapters retain the existing setup.

use std::io;

use abyss_mitm::{FlowOperation, MitmTimeouts, TransparentFlowError};
use tokio::{net::TcpStream, time};
use uuid::Uuid;

use super::{
    DnsResolution, FramedFlowIo, FramedUnixConnection, FramedUnixIngress, configured_target,
    framed_protocol::{FlowFrame, FlowFrameCodec, FlowOpenResult},
};
use crate::ingress::{IngressConnection, IngressError, PlatformFlow, PlatformFlowMetadata};

impl IngressConnection for FramedUnixConnection {
    async fn into_flow(self) -> Result<PlatformFlow, IngressError> {
        let Self {
            proxy,
            mut stream,
            socket_path,
            process_context_resolver,
        } = self;
        let (flow_id, payload) = FramedUnixIngress::read_open_frame(&mut stream).await?;
        let connect_before_open = payload.connect_before_open;
        let preparation = async {
            let target = proxy
                .as_ref()
                .map(|_| configured_target(&payload))
                .transpose()?;
            let metadata = FramedUnixIngress::metadata_from_open(
                payload,
                process_context_resolver,
                if proxy.is_some() {
                    DnsResolution::UpstreamProxy
                } else {
                    DnsResolution::Local
                },
            )
            .await?;
            Ok::<_, IngressError>((metadata, target))
        }
        .await;
        let (metadata, target) = match preparation {
            Ok(prepared) => prepared,
            Err(error) => {
                if connect_before_open {
                    Self::report_failure(&mut stream, flow_id, "connect_failed").await;
                }
                return Err(error);
            }
        };
        let upstream = if !connect_before_open {
            None
        } else if proxy.is_some() {
            Self::send_result(&mut stream, flow_id, FlowOpenResult::Deferred).await?;
            None
        } else {
            match Self::connect_direct(&metadata).await {
                Ok(upstream) => {
                    Self::send_result(&mut stream, flow_id, FlowOpenResult::Connected).await?;
                    Some(upstream)
                }
                Err(source) => {
                    Self::report_failure(&mut stream, flow_id, connection_failure_reason(&source))
                        .await;
                    return Err(IngressError::FramedConnect {
                        flow_id,
                        metadata: Box::new(metadata),
                        source,
                    });
                }
            }
        };

        tracing::info!(
            %flow_id,
            socket_path = %socket_path.display(),
            original_destination = %metadata.original_destination(),
            destination_host = ?metadata.destination_host(),
            fake_ip_candidate = crate::connection::destination_address_range(metadata.original_destination()).is_some(),
            "broker ingress accepted framed Unix flow"
        );
        let flow = PlatformFlow::new(FramedFlowIo::new(stream, flow_id), metadata).with_ingress(
            abyss_mitm::FlowIngress::transparent(
                abyss_mitm::TransparentFlowSource::MacosNetworkExtension,
            ),
        );
        let flow = match proxy.zip(target) {
            Some((proxy, target)) => flow.with_upstream_proxy(proxy, target),
            None => flow,
        };
        Ok(match upstream {
            Some(upstream) => flow.with_prepared_stream(Box::new(upstream)),
            None => flow,
        })
    }
}

impl FramedUnixConnection {
    async fn connect_direct(
        metadata: &PlatformFlowMetadata,
    ) -> Result<TcpStream, TransparentFlowError> {
        let destination = metadata
            .original_destination()
            .socket_addr()
            .ok_or_else(|| TransparentFlowError::Io {
                operation: FlowOperation::ConnectProviderTcp,
                source: io::Error::new(io::ErrorKind::InvalidInput, "direct target is unresolved"),
            })?;
        let connect_timeout = MitmTimeouts::default().upstream_connect;
        tracing::info!(
            original_destination = %destination,
            "broker ingress connecting original upstream destination"
        );
        let stream = time::timeout(connect_timeout, TcpStream::connect(destination))
            .await
            .map_err(|_| TransparentFlowError::Timeout {
                operation: FlowOperation::ConnectProviderTcp,
                timeout: connect_timeout,
            })?
            .map_err(|source| TransparentFlowError::Io {
                operation: FlowOperation::ConnectProviderTcp,
                source,
            })?;
        tracing::info!(
            original_destination = %destination,
            "broker ingress connected original upstream destination"
        );
        Ok(stream)
    }

    async fn send_result(
        stream: &mut tokio::net::UnixStream,
        flow_id: Uuid,
        result: FlowOpenResult,
    ) -> Result<(), IngressError> {
        let frame = FlowFrame::open_result(flow_id, result)
            .map_err(|source| IngressError::framed_protocol("encode FlowOpenResult", source))?;
        FlowFrameCodec::write_frame(stream, &frame)
            .await
            .map_err(|source| IngressError::framed_protocol("write FlowOpenResult", source))
    }

    async fn report_failure(
        stream: &mut tokio::net::UnixStream,
        flow_id: Uuid,
        reason: &'static str,
    ) {
        if let Err(error) =
            Self::send_result(stream, flow_id, FlowOpenResult::Failed { reason }).await
        {
            // Retain the original preparation error for diagnostics even if the
            // adapter has already gone away and cannot receive its result.
            tracing::debug!(%flow_id, %error, "could not report framed connection failure");
        }
    }
}

fn connection_failure_reason(error: &TransparentFlowError) -> &'static str {
    match error {
        TransparentFlowError::Timeout { .. } => "timed_out",
        TransparentFlowError::Io { source, .. } => match source.kind() {
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::ConnectionRefused => "connection_refused",
            io::ErrorKind::HostUnreachable | io::ErrorKind::NetworkUnreachable => {
                "host_unreachable"
            }
            _ => "connect_failed",
        },
        _ => "connect_failed",
    }
}

#[cfg(test)]
mod tests;
