//! Associates WFP connection tracking with every configured next-hop socket.

use std::{io, os::windows::io::AsSocket as _};

use abyss_mitm::outbound::ProxySocketInitializer;
use tokio::net::{TcpSocket, TcpStream};

use super::redirect_records::RedirectRecords;

pub(super) struct WfpSocketInitializer {
    records: RedirectRecords,
}

impl WfpSocketInitializer {
    pub(super) fn query(stream: &TcpStream) -> io::Result<Self> {
        Ok(Self {
            records: RedirectRecords::query(stream.as_socket())?,
        })
    }
}

impl ProxySocketInitializer for WfpSocketInitializer {
    fn initialize(&self, socket: &TcpSocket) -> io::Result<()> {
        self.records.apply(socket.as_socket())
    }
}
