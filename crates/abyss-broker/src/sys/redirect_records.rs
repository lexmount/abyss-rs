//! Transfers opaque WFP redirect records between accepted and outbound sockets.
//!
//! These records describe OS routing history, not HTTP proxy configuration.

use std::os::windows::io::BorrowedSocket;

use windows::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
};

use super::winsock::{self, WinSockError};

pub(crate) struct RedirectRecords(Result<Box<[u8]>, WinSockError>);

impl RedirectRecords {
    pub(crate) fn capture(socket: BorrowedSocket<'_>) -> Self {
        // Bound kernel-provided routing metadata; never continue a CONNECT route
        // without records if recovery fails or the history exceeds this bound.
        Self(winsock::ioctl_output_buffer(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            64 * 1024,
        ))
    }

    pub(crate) fn apply(&self, socket: BorrowedSocket<'_>) -> Result<(), WinSockError> {
        // Defer capture errors to the new CONNECT path. Existing direct flows
        // keep their previous behavior and do not consume these records.
        let records = self.0.as_ref().map_err(|error| *error)?;
        winsock::ioctl_input_buffer(socket, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, records)
    }
}
