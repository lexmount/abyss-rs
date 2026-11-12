//! Resolve and connect a logical target only after the flow's route is selected.

use std::{io, net::SocketAddr, time::Duration};

use futures_util::{StreamExt as _, stream::FuturesUnordered};
use tokio::{
    net::{TcpStream, lookup_host},
    time,
};

use super::super::{FlowOperation, TransparentFlowError};
use crate::{TargetAuthority, outbound::ListenerEndpoint};

pub(super) struct DirectTarget {
    pub(super) target: TargetAuthority,
    pub(super) excluded_listener: Option<SocketAddr>,
}

impl DirectTarget {
    pub(super) async fn connect(
        &self,
        timeout: Duration,
    ) -> Result<TcpStream, TransparentFlowError> {
        time::timeout(timeout, self.resolve_and_connect())
            .await
            .map_err(|_| TransparentFlowError::Timeout {
                operation: FlowOperation::ConnectProviderTcp,
                timeout,
            })?
    }

    async fn resolve_and_connect(&self) -> Result<TcpStream, TransparentFlowError> {
        let addresses = match self.target.host() {
            crate::TargetHost::Ip(ip) => vec![SocketAddr::new(*ip, self.target.port())],
            crate::TargetHost::Dns(host) => lookup_host((host.as_str(), self.target.port()))
                .await
                .map_err(Self::io_error)?
                .collect(),
        };
        if let Some(listener) = self.excluded_listener {
            for address in &addresses {
                if ListenerEndpoint::new(listener)
                    .contains(*address)
                    .map_err(Self::io_error)?
                {
                    return Err(Self::io_error(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "upstream target resolves to the broker listener",
                    )));
                }
            }
        }
        let mut attempts = FuturesUnordered::new();
        for address in addresses {
            attempts.push(TcpStream::connect(address));
        }
        let mut last_error =
            io::Error::new(io::ErrorKind::NotFound, "target resolved to no addresses");
        while let Some(result) = attempts.next().await {
            match result {
                Ok(stream) => return Ok(stream),
                Err(error) => last_error = error,
            }
        }
        Err(Self::io_error(last_error))
    }

    const fn io_error(source: io::Error) -> TransparentFlowError {
        TransparentFlowError::Io {
            operation: FlowOperation::ConnectProviderTcp,
            source,
        }
    }
}
