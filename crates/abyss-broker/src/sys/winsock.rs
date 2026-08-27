//! Safe wrappers for `WinSock` socket IOCTL calls used by redirected flows.

#![expect(
    unsafe_code,
    reason = "WinSock IOCTLs are exposed through raw Windows FFI."
)]

use std::{
    ffi::c_void,
    mem::size_of,
    os::windows::io::{AsRawSocket, BorrowedSocket},
};

use windows::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SOCKET, WSAGetLastError, WSAIoctl,
};

pub const SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT_CODE: u32 =
    SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT;

/// Address-family constants used by the WFP redirect-context ABI.
pub struct AddressFamily;

impl AddressFamily {
    pub fn ipv4() -> u32 {
        u32::from(AF_INET.0)
    }

    pub fn ipv6() -> u32 {
        u32::from(AF_INET6.0)
    }
}

/// Runs `WSAIoctl` with a bounded variable-length output buffer.
///
/// # Errors
///
/// Returns `WinSockError` when the raw socket value cannot be represented by
/// `windows`' `SOCKET` wrapper, when the requested capacity is invalid, when
/// `WSAIoctl` fails, or when the API reports an invalid output length.
pub fn ioctl_output_buffer(
    socket: BorrowedSocket<'_>,
    io_control_code: u32,
    output_capacity: usize,
) -> Result<Box<[u8]>, WinSockError> {
    let socket = SOCKET(
        usize::try_from(socket.as_raw_socket()).map_err(|_| WinSockError::SocketDoesNotFitUsize)?,
    );
    if output_capacity < size_of::<u32>() {
        return Err(WinSockError::OutputBufferTooSmall {
            size: output_capacity,
        });
    }
    let output_size =
        u32::try_from(output_capacity).map_err(|_| WinSockError::OutputBufferTooLarge {
            size: output_capacity,
        })?;
    let mut output = vec![0_u8; output_capacity];
    let mut bytes_returned = 0_u32;

    // SAFETY: `socket` is borrowed from a live owner. The output buffer points
    // to `output_size` writable bytes for the duration of the call, and
    // `bytes_returned` points to a live u32.
    let result = unsafe {
        WSAIoctl(
            socket,
            io_control_code,
            None,
            0,
            Some(output.as_mut_ptr().cast::<c_void>()),
            output_size,
            &raw mut bytes_returned,
            None,
            None,
        )
    };
    if result != 0_i32 {
        // SAFETY: Reads the thread-local WinSock error from the failed call.
        let error = unsafe { WSAGetLastError() };
        return Err(WinSockError::Api { code: error.0 });
    }
    let returned_size =
        usize::try_from(bytes_returned).map_err(|_| WinSockError::OutputLengthDoesNotFitUsize {
            size: bytes_returned,
        })?;
    if returned_size == 0 {
        return Err(WinSockError::EmptyOutput);
    }
    if returned_size > output_capacity {
        return Err(WinSockError::OutputExceedsBuffer {
            capacity: output_capacity,
            actual: returned_size,
        });
    }

    output.truncate(returned_size);
    Ok(output.into_boxed_slice())
}

#[derive(Debug, Clone, Copy)]
pub enum WinSockError {
    Api { code: i32 },
    SocketDoesNotFitUsize,
    OutputBufferTooSmall { size: usize },
    OutputBufferTooLarge { size: usize },
    OutputLengthDoesNotFitUsize { size: u32 },
    EmptyOutput,
    OutputExceedsBuffer { capacity: usize, actual: usize },
}

impl std::fmt::Display for WinSockError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api { code } => write!(formatter, "WinSock error {code}"),
            Self::SocketDoesNotFitUsize => formatter.write_str("socket handle does not fit usize"),
            Self::OutputBufferTooSmall { size } => {
                write!(formatter, "output buffer size {size} is smaller than a u32")
            }
            Self::OutputBufferTooLarge { size } => {
                write!(formatter, "output buffer size {size} does not fit in u32")
            }
            Self::OutputLengthDoesNotFitUsize { size } => {
                write!(
                    formatter,
                    "WinSock output length {size} does not fit in usize"
                )
            }
            Self::EmptyOutput => formatter.write_str("WinSock returned an empty output buffer"),
            Self::OutputExceedsBuffer { capacity, actual } => {
                write!(
                    formatter,
                    "WinSock reported {actual} output bytes for a {capacity}-byte buffer"
                )
            }
        }
    }
}

impl std::error::Error for WinSockError {}
