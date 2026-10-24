//! Shared response and plugin assertions for native framed-ingress scenarios.

use std::{io::Read as _, os::unix::net::UnixStream};

use super::REST_TIMEOUT;

pub fn assert_no_event(plugin: &mut UnixStream) {
    plugin
        .set_read_timeout(Some(std::time::Duration::from_millis(500)))
        .unwrap();
    let error = plugin.read(&mut [0_u8; 4]).unwrap_err();
    assert!(
        matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
        ),
        "no event should arrive for disabled or unidentified traffic: {error}"
    );
    plugin.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
}

#[expect(
    clippy::big_endian_bytes,
    reason = "Ingress frame lengths are network byte order."
)]
pub fn read_response(stream: &mut UnixStream) -> Vec<u8> {
    let mut response = Vec::new();
    loop {
        let mut header = [0_u8; 28];
        stream.read_exact(&mut header).unwrap();
        assert_eq!(
            &header[..4],
            b"ABY1",
            "response must use the framed ingress protocol"
        );
        let len = u32::from_be_bytes([header[24], header[25], header[26], header[27]]);
        assert!(
            len < 0x0100_0000,
            "response frame must stay within the protocol size limit"
        );
        let mut payload = vec![0_u8; usize::try_from(len).unwrap()];
        stream.read_exact(&mut payload).unwrap();
        if header[4..6] == [2, 2] {
            response.extend_from_slice(&payload);
        }
        if header[4..6] == [3, 2] {
            return response;
        }
        assert_ne!(header[4], 4, "broker returned flow error: {payload:?}");
    }
}
