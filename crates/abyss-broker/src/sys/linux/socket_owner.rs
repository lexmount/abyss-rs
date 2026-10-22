//! Resolve a loopback TCP client to its unique, visible procfs socket owner.
//! Reads are bounded and uncached; ambiguous or unavailable ownership fails closed.

use std::{
    fs,
    io::Read as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::Path,
    time::{Duration, Instant},
};

const MAX_TABLE_BYTES: u64 = 0x0020_0000;
const MAX_PROCESSES: usize = 8192;
const MAX_DESCRIPTORS: usize = 0x0002_0000;
const LOOKUP_BUDGET: Duration = Duration::from_millis(250);

#[derive(PartialEq)]
struct SocketOwner {
    inode: u64,
    uid: u32,
}

pub fn connection_pid(peer: SocketAddr, local: SocketAddr) -> Option<u32> {
    let peer = canonical_address(peer);
    let local = canonical_address(local);
    if !peer.ip().is_loopback() || !local.ip().is_loopback() {
        return None;
    }
    let deadline = Instant::now().checked_add(LOOKUP_BUDGET)?;
    let owner = socket_owner(peer, local)?;
    let pid = owner.find_pid(deadline)?;
    // The original socket must still be connected after walking the fd tables.
    (socket_owner(peer, local)? == owner).then_some(pid)
}

impl SocketOwner {
    fn find_pid(&self, deadline: Instant) -> Option<u32> {
        let mut result = None;
        let mut descriptors = 0_usize;
        let socket_link = format!("socket:[{}]", self.inode);
        for (index, process) in fs::read_dir("/proc").ok()?.enumerate() {
            if index >= MAX_PROCESSES || Instant::now() >= deadline {
                return None;
            }
            let process = process.ok()?;
            let Some(pid) = process
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            else {
                continue;
            };
            // A process may inherit a socket and then change user IDs. Inspect
            // all visible fd tables instead of filtering by the socket's UID.
            let Ok(files) = fs::read_dir(process.path().join("fd")) else {
                continue;
            };
            for file in files {
                descriptors = descriptors.saturating_add(1);
                if descriptors > MAX_DESCRIPTORS || Instant::now() >= deadline {
                    return None;
                }
                let Ok(file) = file else { continue };
                if fs::read_link(file.path()).is_ok_and(|link| link == Path::new(&socket_link)) {
                    if result.is_some_and(|previous| previous != pid) {
                        return None;
                    }
                    result = Some(pid);
                    break;
                }
            }
        }
        result
    }
}

fn socket_owner(peer: SocketAddr, local: SocketAddr) -> Option<SocketOwner> {
    let mut result = None;
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let file = match fs::File::open(table) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => return None,
        };
        let mut bytes = Vec::new();
        file.take(MAX_TABLE_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
            .ok()?;
        if u64::try_from(bytes.len()).ok()? > MAX_TABLE_BYTES {
            return None;
        }
        let text = std::str::from_utf8(&bytes).ok()?;
        for line in text.lines().skip(1) {
            if let Some(owner) = parse_socket_owner(line, peer, local) {
                if result.is_some() {
                    return None;
                }
                result = Some(owner);
            }
        }
    }
    result
}

fn parse_socket_owner(line: &str, peer: SocketAddr, local: SocketAddr) -> Option<SocketOwner> {
    let mut fields = line.split_ascii_whitespace();
    fields.next()?;
    if parse_address(fields.next()?)? != peer
        || parse_address(fields.next()?)? != local
        || fields.next()? != "01"
    {
        return None;
    }
    let uid = fields.nth(3)?.parse().ok()?;
    let inode = fields.nth(1)?.parse().ok()?;
    (inode != 0_u64).then_some(SocketOwner { inode, uid })
}

fn parse_address(value: &str) -> Option<SocketAddr> {
    let (hex, port) = value.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match hex.len() {
        8 => IpAddr::V4(Ipv4Addr::from(
            u32::from_str_radix(hex, 16).ok()?.to_ne_bytes(),
        )),
        32 => {
            let mut bytes = [0_u8; 16];
            for (index, word) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
                let start = index.checked_mul(8)?;
                *word = u32::from_str_radix(hex.get(start..start.checked_add(8)?)?, 16)
                    .ok()?
                    .to_ne_bytes();
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => return None,
    };
    Some(canonical_address(SocketAddr::new(ip, port)))
}

const fn canonical_address(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip().to_canonical(), address.port())
}

#[cfg(test)]
mod tests {
    use super::{connection_pid, parse_address, parse_socket_owner, socket_owner};
    use std::{
        fmt::Write as _,
        net::{TcpListener, TcpStream},
        os::fd::OwnedFd,
        process::{Command, Stdio},
        time::Instant,
    };

    #[test]
    fn matches_established_client_tuple_and_rejects_reversed_or_listening_sockets() {
        let peer = "127.0.0.1:40000".parse().unwrap();
        let local = "127.0.0.1:8080".parse().unwrap();
        let ip = format!("{:08X}", u32::from_ne_bytes([127, 0, 0, 1]));
        let line = format!("0: {ip}:9C40 {ip}:1F90 01 0:0 00:0 0 1000 0 1234 1");
        let owner = parse_socket_owner(&line, peer, local).unwrap();
        assert_eq!(owner.inode, 1234);
        assert_eq!(owner.uid, 1000);
        assert!(parse_socket_owner(&line, local, peer).is_none());
        assert!(parse_socket_owner(&line.replace(" 01 ", " 0A "), peer, local).is_none());
        assert!(parse_socket_owner("malformed", peer, local).is_none());
    }

    #[test]
    fn decodes_ipv6_native_words_and_ipv4_mapped_addresses() {
        for ip in ["::1", "::ffff:127.0.0.1"] {
            let ip: std::net::Ipv6Addr = ip.parse().unwrap();
            let mut hex = String::new();
            for word in ip.octets().as_chunks::<4>().0 {
                write!(hex, "{:08X}", u32::from_ne_bytes(*word)).unwrap();
            }
            assert_eq!(
                parse_address(&format!("{hex}:1F90")).unwrap().ip(),
                std::net::IpAddr::V6(ip).to_canonical()
            );
        }
        assert!(parse_address("bad:1F90").is_none());
    }

    #[test]
    fn finds_current_process_for_real_ipv4_and_ipv6_connections() {
        for address in ["127.0.0.1:0", "[::1]:0"] {
            let listener = TcpListener::bind(address).unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (accepted, _) = listener.accept().unwrap();
            assert_eq!(
                connection_pid(client.local_addr().unwrap(), accepted.local_addr().unwrap()),
                Some(std::process::id())
            );
        }
    }

    #[test]
    fn shared_socket_ownership_is_not_attributed_to_an_arbitrary_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let inherited: OwnedFd = client.try_clone().unwrap().into();
        let mut child = Command::new("/bin/cat")
            .stdin(Stdio::from(inherited))
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let result = connection_pid(client.local_addr().unwrap(), accepted.local_addr().unwrap());
        drop(child.kill());
        child.wait().unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn expired_lookup_budget_does_not_scan_processes() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let owner =
            socket_owner(client.local_addr().unwrap(), accepted.local_addr().unwrap()).unwrap();
        assert_eq!(owner.find_pid(Instant::now()), None);
    }

    #[test]
    fn remote_peers_are_not_assigned_a_local_pid() {
        assert_eq!(
            connection_pid(
                "192.0.2.1:40000".parse().unwrap(),
                "127.0.0.1:8080".parse().unwrap()
            ),
            None
        );
    }
}
