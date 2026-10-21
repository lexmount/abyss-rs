//! Real macOS process attribution and TLS routing through the broker's framed ingress.

use std::{
    collections::VecDeque,
    fs,
    io::{self, Read as _, Write as _},
    net::TcpListener,
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::{PrivatePkcs8KeyDer, ServerName},
};
use serde_json::json;
use uuid::Uuid;

use super::{
    BrokerProcess, REST_TIMEOUT, client, loopback_ephemeral_addr, read_auth_token,
    reserve_api_loopback_addr, update_mitm_config, url, write_flow_frame,
};

#[test]
fn real_entry_script_selects_opaque_tls_without_bypassing_sibling_processes() {
    let api_addr = reserve_api_loopback_addr();
    let socket_path = std::env::temp_dir().join(format!("entry-{}.sock", Uuid::new_v4()));
    let mut broker = BrokerProcess::spawn_framed_unix(api_addr, &socket_path);
    broker.wait_for_running();
    let token = read_auth_token(&broker.auth_token_file);
    update_mitm_config(
        api_addr,
        &token,
        &json!({
            "tls_decryption": {
                "default_action":"intercept",
                "rules":[{
                    "id":"background-entry", "action":"passthrough",
                    "application_ids":["com.example.agent"],
                    "process_entry_points":["Contents/Resources/app.asar/main/daemon.js"]
                }]
            }
        }),
    );
    let fixture_root = broker.runtime_root.join("My Agent.app");
    for (entry, application, bypass) in [
        (
            "Contents/Resources/app.asar/main/daemon.js",
            "com.example.agent",
            true,
        ),
        (
            "Contents/Resources/app.asar.unpacked/cli/bin/agent",
            "com.example.agent",
            false,
        ),
        (
            "Contents/Resources/app.asar/main/daemon.js",
            "com.other.agent",
            false,
        ),
    ] {
        let process = ScriptProcess::spawn(&fixture_root, entry);
        let flow_id = Uuid::new_v4();
        let succeeded = tls_request(&socket_path, &process, application, flow_id);
        assert_eq!(
            succeeded,
            bypass,
            "entry {entry}, app {application}: {}",
            broker.read_log()
        );
        let deadline = std::time::Instant::now()
            .checked_add(REST_TIMEOUT)
            .expect("test deadline should fit Instant");
        loop {
            let diagnostics: serde_json::Value = client()
                .get(url(api_addr, "/v1/support/diagnostics"))
                .bearer_auth(&token)
                .send()
                .unwrap()
                .json()
                .unwrap();
            if let Some(flow) = diagnostics["flow"]["recent_flows"]
                .as_array()
                .unwrap()
                .iter()
                .find(|flow| flow["source_process"]["pid"] == process.child.id())
            {
                assert_eq!(flow["source_process"]["entry_point"], entry);
                if bypass {
                    assert_eq!(flow["decision"], "passthrough");
                } else {
                    assert_ne!(flow["decision"], "passthrough");
                }
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "flow diagnostics missing: {}",
                broker.read_log()
            );
            thread::sleep(super::POLL_INTERVAL);
        }
    }
    broker.shutdown();
    broker.wait_for_exit();
}

struct ScriptProcess {
    child: Child,
    executable: PathBuf,
}

impl ScriptProcess {
    fn spawn(bundle: &Path, entry: &str) -> Self {
        let executable = bundle.join("Contents/MacOS/Electron");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        if !executable.exists() {
            fs::copy("/bin/cat", &executable).unwrap();
            // A relocated Apple platform binary needs a local test signature.
            assert!(
                Command::new("/usr/bin/codesign")
                    .args(["--force", "--sign", "-"])
                    .arg(&executable)
                    .output()
                    .unwrap()
                    .status
                    .success(),
                "the relocated native fixture must be signed"
            );
        }
        let script = bundle.join(entry);
        fs::create_dir_all(script.parent().unwrap()).unwrap();
        fs::write(&script, "").unwrap();
        // A real native process with the same argv shape as a bundled runtime.
        // It reads the empty entry file, then waits on stdin until dropped.
        let mut child = Command::new(&executable)
            .arg(&script)
            .arg("-")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // Wait for exec so KERN_PROCARGS2 cannot observe the pre-exec parent image.
        thread::sleep(std::time::Duration::from_millis(100));
        assert!(
            child.try_wait().unwrap().is_none(),
            "entry fixture must remain alive"
        );
        Self { child, executable }
    }
}

impl Drop for ScriptProcess {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

fn tls_request(socket: &Path, process: &ScriptProcess, application: &str, flow_id: Uuid) -> bool {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let certificate = certified.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der());
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())
        .unwrap();
    let upstream = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
    let address = upstream.local_addr().unwrap();
    upstream.set_nonblocking(true).unwrap();
    let finished = Arc::new(AtomicBool::new(false));
    let server_finished = finished.clone();
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now()
            .checked_add(REST_TIMEOUT)
            .expect("test deadline should fit Instant");
        let socket = loop {
            match upstream.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if server_finished.load(Ordering::Acquire)
                        || std::time::Instant::now() >= deadline
                    {
                        return;
                    }
                    thread::sleep(super::POLL_INTERVAL);
                }
                Err(error) => panic!("upstream accept failed: {error}"),
            }
        };
        socket.set_nonblocking(false).unwrap();
        socket.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
        socket.set_write_timeout(Some(REST_TIMEOUT)).unwrap();
        let mut tls = StreamOwned::new(
            ServerConnection::new(Arc::new(server_config)).unwrap(),
            socket,
        );
        let mut request = [0_u8; 2048];
        if let Ok(size) = tls.read(&mut request) {
            if !request[..size].starts_with(b"GET /opaque ") {
                return;
            }
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .unwrap();
            tls.conn.send_close_notify();
            drop(tls.flush());
        }
    });
    let mut roots = RootCertStore::empty();
    // The client trusts only the upstream fixture, never the broker's CA.
    roots.add(certificate).unwrap();
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connection =
        ClientConnection::new(Arc::new(config), ServerName::try_from("localhost").unwrap())
            .unwrap();
    let mut transport = FramedTransport {
        socket: UnixStream::connect(socket).unwrap(),
        flow_id,
        buffered: VecDeque::new(),
        closed: false,
    };
    transport
        .socket
        .set_read_timeout(Some(REST_TIMEOUT))
        .unwrap();
    transport
        .socket
        .set_write_timeout(Some(REST_TIMEOUT))
        .unwrap();
    let payload = serde_json::to_vec(&json!({
        "flow_id":flow_id,"platform":"macos","protocol":"tcp",
        "source_pid":process.child.id(),"source_pid_version":null,
        "source_process":process.executable,"source_application_id":application,
        "destination_host":"localhost","destination_ip":address.ip(),
        "destination_port":address.port(),"original_tls_sni":null
    }))
    .unwrap();
    write_flow_frame(&mut transport.socket, 1, 0, flow_id, &payload);
    let mut tls = StreamOwned::new(connection, transport);
    let result = (|| -> io::Result<bool> {
        tls.write_all(b"GET /opaque HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
        let mut response = Vec::new();
        tls.read_to_end(&mut response)?;
        Ok(response.ends_with(b"ok"))
    })()
    .unwrap_or(false);
    drop(tls);
    finished.store(true, Ordering::Release);
    server.join().unwrap();
    result
}

struct FramedTransport {
    socket: UnixStream,
    flow_id: Uuid,
    buffered: VecDeque<u8>,
    closed: bool,
}

impl io::Write for FramedTransport {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        write_flow_frame(&mut self.socket, 2, 1, self.flow_id, bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

impl io::Read for FramedTransport {
    #[expect(
        clippy::big_endian_bytes,
        reason = "The framed ingress wire length is network byte order."
    )]
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        while self.buffered.is_empty() && !self.closed {
            let mut header = [0_u8; 28];
            self.socket.read_exact(&mut header)?;
            if &header[..4] != b"ABY1" {
                return Err(io::Error::other("invalid frame"));
            }
            let length = u32::from_be_bytes([header[24], header[25], header[26], header[27]]);
            if length > 0x0100_0000 {
                return Err(io::Error::other("oversized frame"));
            }
            let mut payload = vec![
                0_u8;
                usize::try_from(length)
                    .map_err(|_| io::Error::other("frame size overflow"))?
            ];
            self.socket.read_exact(&mut payload)?;
            if header[4] == 2 && header[5] == 2 {
                self.buffered.extend(payload);
            }
            if matches!(header[4], 3 | 4) {
                self.closed = true;
            }
        }
        let size = bytes.len().min(self.buffered.len());
        for byte in &mut bytes[..size] {
            *byte = self
                .buffered
                .pop_front()
                .ok_or_else(|| io::Error::other("missing buffered byte"))?;
        }
        Ok(size)
    }
}
