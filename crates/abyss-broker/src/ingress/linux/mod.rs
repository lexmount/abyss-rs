//! Linux TUN adapter: preconfigured IP packets become broker TCP flows.
//!
//! Interface provisioning and policy routing belong to the administrator.
//! This module preserves kernel network configuration and runs unprivileged
//! when the persistent TUN device is assigned to the broker's user.

mod device;
mod stack;

use std::{io, path::Path, time::Duration};

use abyss_mitm::{DestinationAddress, FlowIngress, TargetAuthority, TransparentFlowSource};
use thiserror::Error;
use tokio::{sync::mpsc, task::JoinHandle};
use tun_rs::{AsyncDevice, DeviceBuilder};

use super::{
    Ingress, IngressError, IngressFactory, IngressRuntimeStatus, PlatformFlow,
    PlatformFlowMetadata, StartedIngress,
};
use crate::network_config::NetworkRuntime;
use stack::{FlowKey, TcpStack};

/// Validated administrator-provisioned TUN endpoint.
#[derive(Debug, Clone, PartialEq)]
pub struct IngressEndpoint {
    device_name: String,
}

impl IngressEndpoint {
    /// Creates an endpoint after startup configuration validates its name.
    pub const fn new(device_name: String) -> Self {
        Self { device_name }
    }

    /// Returns the administrator's interface name for diagnostics.
    pub fn endpoint_label(&self) -> String {
        self.device_name.clone()
    }

    /// Binds new flows to the shared network routing policy.
    pub const fn into_factory(self, network: NetworkRuntime) -> TunIngressFactory {
        TunIngressFactory {
            endpoint: self,
            network,
        }
    }
}

/// Attaches to an existing TUN without changing network configuration.
pub struct TunIngressFactory {
    endpoint: IngressEndpoint,
    network: NetworkRuntime,
}

impl IngressFactory for TunIngressFactory {
    type Ingress = TunIngress;

    async fn start(self) -> Result<StartedIngress<Self::Ingress>, IngressError> {
        let (name, device, mtu) = tokio::task::spawn_blocking(move || {
            let name = self.endpoint.device_name;
            let device = Self::attach(&name)?;
            let mtu = device.mtu()?;
            Ok::<_, io::Error>((name, device, mtu))
        })
        .await
        .map_err(TunIngressError::Task)?
        .map_err(TunIngressError::Io)?;
        if mtu < 1280 {
            return Err(TunIngressError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "TUN MTU must be at least 1280 for IPv4/IPv6 TCP",
            ))
            .into());
        }
        let (sender, receiver) = mpsc::channel(32);
        let task = tokio::spawn(async move {
            if let Err(error) = Self::run(device, usize::from(mtu), self.network, sender).await {
                tracing::error!(%error, "Linux TUN packet task failed");
            }
        });
        Ok(StartedIngress::new(
            TunIngress {
                receiver,
                task: Some(task),
            },
            IngressRuntimeStatus::LinuxTun { device_name: name },
        ))
    }
}

impl TunIngressFactory {
    fn attach(name: &str) -> io::Result<AsyncDevice> {
        // Refuse to create an unconfigured interface even if the broker was
        // accidentally launched with CAP_NET_ADMIN. Names are validated by config.
        let flags =
            std::fs::read_to_string(Path::new("/sys/class/net").join(name).join("tun_flags"))?;
        let flags = u32::from_str_radix(flags.trim().trim_start_matches("0x"), 16)
            .map_err(io::Error::other)?;
        if flags & 1 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "device must be a TUN, not a TAP",
            ));
        }
        DeviceBuilder::new()
            .name(name)
            .inherit_enable_state()
            .build_async()
    }

    #[expect(
        clippy::integer_division_remainder_used,
        reason = "tokio::select! uses remainder internally"
    )]
    async fn run(
        device: AsyncDevice,
        mtu: usize,
        network: NetworkRuntime,
        sender: mpsc::Sender<PlatformFlow>,
    ) -> io::Result<()> {
        let mut stack = TcpStack::new(mtu);
        let epoch = std::time::Instant::now();
        let mut timer = tokio::time::interval(Duration::from_millis(5));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut packet = vec![0; 0xFFFF].into_boxed_slice();
        loop {
            tokio::select! {
                result = device.recv(&mut packet) => {
                    let size = result?;
                    if size <= mtu {
                        stack.receive(packet[..size].into());
                    }
                }
                _ = timer.tick() => {}
                () = sender.closed() => return Ok(()),
            }
            let elapsed = i64::try_from(epoch.elapsed().as_millis()).unwrap_or(i64::MAX);
            stack.poll(
                smoltcp::time::Instant::from_millis(elapsed),
                |key, stream| sender.try_send(Self::flow(key, stream, &network)).is_ok(),
            );
            while let Some(packet) = stack.device.outgoing.pop_front() {
                if device.send(&packet).await? != packet.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short TUN packet write",
                    ));
                }
            }
        }
    }

    fn flow(
        key: &FlowKey,
        stream: tokio::io::DuplexStream,
        network: &NetworkRuntime,
    ) -> PlatformFlow {
        let metadata = PlatformFlowMetadata::from_destination_parts(
            Some(key.source),
            None,
            DestinationAddress::Known(key.destination),
            None,
            None,
        );
        let flow = PlatformFlow::new(stream, metadata).with_ingress(FlowIngress::transparent(
            TransparentFlowSource::LinuxTransparent,
        ));
        match network.snapshot().proxy() {
            Some(proxy) => flow.with_upstream_proxy(
                proxy.clone(),
                TargetAuthority::parse(&key.destination.to_string())
                    .expect("socket address is an authority"),
            ),
            None => flow,
        }
    }
}

/// Listener owns its packet task until explicit async shutdown or cancellation.
pub struct TunIngress {
    receiver: mpsc::Receiver<PlatformFlow>,
    task: Option<JoinHandle<()>>,
}

impl Ingress for TunIngress {
    type Accepted = PlatformFlow;

    async fn accept(&mut self) -> Result<PlatformFlow, IngressError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| TunIngressError::Stopped.into())
    }

    async fn shutdown(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
            if let Err(error) = task.await
                && !error.is_cancelled()
            {
                tracing::warn!(%error, "Linux TUN task failed");
            }
        }
    }
}

impl Drop for TunIngress {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

#[derive(Debug, Error)]
pub enum TunIngressError {
    #[error("Linux TUN attachment task failed: {0}")]
    Task(#[source] tokio::task::JoinError),
    #[error("Linux TUN IO failed: {0}")]
    Io(#[source] io::Error),
    #[error("Linux TUN packet task stopped; check the configured interface")]
    Stopped,
}
