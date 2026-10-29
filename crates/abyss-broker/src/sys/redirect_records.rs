//! Owns opaque WFP redirect records and transfers them to outbound sockets.
//!
//! These OS records are distinct from the callout driver's destination context.
//! Their contents are never decoded or synthesized by the broker.

use std::{io, os::windows::io::BorrowedSocket};

use windows::Win32::Networking::WinSock::{
    SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, WSAEFAULT,
};

use super::winsock::{self, WinSockError};

const INITIAL_RECORD_CAPACITY: usize = 1024;
// Bound allocation for the variable-size OS record chain before retrying.
const MAX_RECORD_CAPACITY: usize = 1024 * 1024;

#[repr(transparent)]
pub struct RedirectRecords {
    inner: Box<[u8]>,
}

impl RedirectRecords {
    pub fn query(socket: BorrowedSocket<'_>) -> io::Result<Self> {
        let query = |capacity| {
            winsock::ioctl_output_buffer(
                socket,
                SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
                capacity,
            )
        };
        let mut capacity = INITIAL_RECORD_CAPACITY;
        loop {
            match query(capacity) {
                Ok(inner) => return Ok(Self { inner }),
                Err(WinSockError::InsufficientBuffer { required }) => {
                    let next = Self::retry_capacity(required)?;
                    if next <= capacity {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "WFP record size did not grow",
                        ));
                    }
                    capacity = next;
                }
                // WSAIoctl may signal a short buffer without a required length.
                // All supplied pointers are valid; retry only this documented
                // sizing error, with bounded geometric growth and no decoding.
                Err(WinSockError::Api { code })
                    if code == WSAEFAULT.0 && capacity < MAX_RECORD_CAPACITY =>
                {
                    capacity = capacity.saturating_mul(2).min(MAX_RECORD_CAPACITY);
                }
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "query WFP redirect records ({capacity} bytes): {error}"
                    )));
                }
            }
        }
    }

    fn retry_capacity(required: u32) -> io::Result<usize> {
        usize::try_from(required)
            .ok()
            .filter(|size| *size > INITIAL_RECORD_CAPACITY && *size <= MAX_RECORD_CAPACITY)
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid WFP redirect record size",
                )
            })
    }

    pub fn apply(&self, socket: BorrowedSocket<'_>) -> io::Result<()> {
        winsock::ioctl_input_buffer(socket, SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, &self.inner)
            .map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::RedirectRecords;

    #[test]
    fn record_size_retry_is_bounded_and_must_grow() {
        for size in [0, 4, 1024, 1024 * 1024 + 1, u32::MAX] {
            assert!(RedirectRecords::retry_capacity(size).is_err());
        }
        for size in [1025, 1024 * 1024] {
            assert_eq!(
                RedirectRecords::retry_capacity(size).unwrap(),
                usize::try_from(size).unwrap()
            );
        }
    }

    #[tokio::test]
    async fn ordinary_socket_has_no_wfp_records() {
        use std::os::windows::io::AsSocket as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, _) = listener.accept().await.unwrap();
        assert!(
            RedirectRecords::query(accepted.as_socket()).is_err(),
            "unredirected sockets must not gain fabricated tracking records"
        );
        drop(client);
    }
}
