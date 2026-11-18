//! Packet validation and socket admission regression tests.

use tokio_smoltcp::smoltcp::wire::{IpAddress, IpProtocol, Ipv4Packet, TcpPacket, TcpSeqNumber};

use super::{PacketHeader, SOCKET_LIMIT, TcpStack};
use tokio::sync::mpsc;

fn syn(port: u16) -> Vec<u8> {
    let mut packet = vec![0; 40];
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
    let key = PacketHeader::parse(&syn(12000)).expect("valid TCP SYN").key;
    assert_eq!(key.source.to_string(), "192.0.2.2:12000");
    assert_eq!(key.destination.to_string(), "198.51.100.9:443");
}

#[tokio::test]
async fn invalid_or_truncated_packets_cannot_allocate_connections() {
    let mut packet = syn(12000);
    packet[36] ^= 1;
    assert!(
        PacketHeader::parse(&packet).is_none(),
        "corrupt TCP checksum"
    );
    let valid = syn(12000);
    for length in 0..valid.len() {
        assert!(
            PacketHeader::parse(&valid[..length]).is_none(),
            "truncated packet at {length}"
        );
    }
    let (outgoing, _output) = mpsc::channel(256);
    let (accepted, _connections) = mpsc::channel(32);
    let mut stack = TcpStack::new(1500, outgoing, accepted);
    stack.receive(packet).await.unwrap();
    assert!(
        stack.flows.is_empty(),
        "invalid packets must not consume socket capacity"
    );
    drop(stack);
}

#[tokio::test]
async fn duplicate_syn_does_not_allocate_a_second_socket() {
    let (outgoing, _output) = mpsc::channel(256);
    let (accepted, _connections) = mpsc::channel(32);
    let mut stack = TcpStack::new(1500, outgoing, accepted);
    stack.receive(syn(12000)).await.unwrap();
    stack.receive(syn(12000)).await.unwrap();
    assert_eq!(
        stack.flows.len(),
        1,
        "retransmitted SYN reuses socket admission"
    );
    drop(stack);
}

#[tokio::test]
async fn pending_connections_share_the_global_socket_limit() {
    let (outgoing, _output) = mpsc::channel(256);
    let (accepted, _connections) = mpsc::channel(32);
    let mut stack = TcpStack::new(1500, outgoing, accepted);
    for port in 1..=u16::try_from(SOCKET_LIMIT.saturating_add(1)).unwrap() {
        stack.receive(syn(port)).await.unwrap();
    }
    assert_eq!(
        stack.flows.len(),
        SOCKET_LIMIT,
        "pending handshakes must be bounded"
    );
    drop(stack);
}

#[tokio::test(start_paused = true)]
async fn abandoned_handshakes_release_admission_capacity() {
    let (outgoing, _output) = mpsc::channel(256);
    let (accepted, _connections) = mpsc::channel(32);
    let mut stack = TcpStack::new(1500, outgoing, accepted);
    stack.receive(syn(12000)).await.unwrap();
    tokio::task::yield_now().await;
    tokio::time::advance(std::time::Duration::from_secs(31)).await;
    stack.reap().await.unwrap();
    assert_eq!(
        stack.permits.available_permits(),
        SOCKET_LIMIT,
        "expired accepts release their permits"
    );
    stack.receive(syn(12001)).await.unwrap();
    assert_eq!(
        stack.flows.len(),
        1,
        "dead routing entries must be pruned before the next admission"
    );
    drop(stack);
}

#[tokio::test]
async fn packets_without_a_valid_opening_cannot_reserve_capacity() {
    let (outgoing, _output) = mpsc::channel(256);
    let (accepted, _connections) = mpsc::channel(32);
    let mut stack = TcpStack::new(1500, outgoing, accepted);
    let mut acknowledgement = syn(12000);
    let mut tcp = TcpPacket::new_unchecked(&mut acknowledgement[20..]);
    tcp.set_syn(false);
    tcp.set_ack(true);
    stack.receive(acknowledgement).await.unwrap();
    stack.receive(syn(0)).await.unwrap();
    assert_eq!(stack.permits.available_permits(), SOCKET_LIMIT);
    assert!(stack.flows.is_empty());
    drop(stack);
}

#[tokio::test]
async fn congested_input_does_not_stall_the_shared_packet_driver() {
    let (outgoing, _output) = mpsc::channel(256);
    let (accepted, _connections) = mpsc::channel(32);
    let mut stack = TcpStack::new(1500, outgoing, accepted);
    // No reactor yield: repeated SYNs saturate this flow's bounded input queue.
    for _ in 0..64_u8 {
        stack.receive(syn(12000)).await.unwrap();
    }
    stack.receive(syn(12001)).await.unwrap();
    assert_eq!(stack.flows.len(), 2, "other flows must still be admitted");
    assert_eq!(stack.permits.available_permits(), SOCKET_LIMIT - 2);
    drop(stack);
}
