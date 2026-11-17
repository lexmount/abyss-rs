//! Packet validation and socket admission regression tests.

use smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};

use super::{FlowKey, SOCKET_LIMIT, TcpStack};

fn syn(port: u16) -> Box<[u8]> {
    let mut packet = vec![0; 40].into_boxed_slice();
    let source = [192, 0, 2, 2].into();
    let destination = [198, 51, 100, 9].into();
    {
        let mut ip = Ipv4Packet::new_unchecked(&mut packet[..]);
        ip.set_version(4);
        ip.set_header_len(20);
        ip.set_total_len(40);
        ip.set_hop_limit(64);
        ip.set_next_header(IpProtocol::Tcp);
        ip.set_src_addr(source);
        ip.set_dst_addr(destination);
        ip.fill_checksum();
    }
    let mut tcp = TcpPacket::new_unchecked(&mut packet[20..]);
    tcp.set_src_port(port);
    tcp.set_dst_port(443);
    tcp.set_seq_number(TcpSeqNumber(1));
    tcp.set_header_len(20);
    tcp.set_syn(true);
    tcp.set_window_len(0x8000);
    tcp.fill_checksum(&IpAddress::from(source), &IpAddress::from(destination));
    packet
}

#[test]
fn syn_preserves_both_endpoints() {
    let key = FlowKey::from_syn(&syn(12000)).expect("valid TCP SYN");
    assert_eq!(key.source.to_string(), "192.0.2.2:12000");
    assert_eq!(key.destination.to_string(), "198.51.100.9:443");
}

#[test]
fn invalid_or_truncated_packets_cannot_allocate_connections() {
    let mut packet = syn(12000);
    packet[36] ^= 1;
    assert!(FlowKey::from_syn(&packet).is_none(), "corrupt TCP checksum");
    let valid = syn(12000);
    for length in 0..valid.len() {
        assert!(
            FlowKey::from_syn(&valid[..length]).is_none(),
            "truncated packet at {length}"
        );
    }
    let mut stack = TcpStack::new(1500);
    stack.receive(packet);
    assert!(
        stack.flows.is_empty(),
        "invalid packets must not consume socket capacity"
    );
}

#[test]
fn duplicate_syn_does_not_allocate_a_second_socket() {
    let mut stack = TcpStack::new(1500);
    stack.receive(syn(12000));
    stack.receive(syn(12000));
    assert_eq!(
        stack.flows.len(),
        1,
        "retransmitted SYN reuses socket admission"
    );
}

#[test]
fn pending_connections_share_the_global_socket_limit() {
    let mut stack = TcpStack::new(1500);
    for port in 1..=u16::try_from(SOCKET_LIMIT.saturating_add(1)).unwrap() {
        stack.receive(syn(port));
    }
    assert_eq!(
        stack.flows.len(),
        SOCKET_LIMIT,
        "pending handshakes must be bounded"
    );
}

#[test]
fn abandoned_handshakes_release_admission_capacity() {
    let mut stack = TcpStack::new(1500);
    stack.receive(syn(12000));
    stack.poll(smoltcp::time::Instant::from_millis(31_000_i64), |_, _| {
        panic!("an unacknowledged SYN must not become a broker connection")
    });
    assert!(stack.flows.is_empty(), "incomplete handshakes must expire");
}
