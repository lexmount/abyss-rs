//! Real Linux TCP ownership, procfs entry attribution, and TLS policy routing.

use std::{
    fs,
    io::{self, Read as _, Write as _},
    net::TcpListener,
    path::Path,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::Instant,
};

use rustls::{ServerConfig, ServerConnection, StreamOwned, pki_types::PrivatePkcs8KeyDer};
use serde_json::json;

use super::{
    BrokerProcess, REST_TIMEOUT, client, loopback_ephemeral_addr, read_auth_token,
    reserve_api_loopback_addr, update_mitm_config, url,
};

const CLIENT_SCRIPT: &str = r"
import socket, ssl, sys
proxy_port, upstream_port, ca_path = sys.argv[1:4]
connection = socket.create_connection(('127.0.0.1', int(proxy_port)), timeout=10)
connection.sendall(('CONNECT localhost:' + upstream_port + ' HTTP/1.1\r\nHost: localhost\r\n\r\n').encode())
response = b''
while not response.endswith(b'\r\n\r\n'):
    response += connection.recv(1)
assert response.startswith(b'HTTP/1.1 200'), response
try:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=ca_path)
    connection = context.wrap_socket(connection, server_hostname='localhost')
    connection.sendall(b'GET /opaque HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n')
    response = b''
    while True:
        part = connection.recv(4096)
        if not part: break
        response += part
    print('passthrough' if response.endswith(b'ok') else 'unexpected response')
except ssl.SSLCertVerificationError:
    print('intercepted')
finally:
    connection.close()
";

#[test]
fn linux_explicit_proxy_matches_only_the_real_client_entry_point() {
    let api_addr = reserve_api_loopback_addr();
    let mut broker = BrokerProcess::spawn_explicit(api_addr, loopback_ephemeral_addr());
    let proxy = broker.wait_for_running().listen_addr.unwrap();
    let token = read_auth_token(&broker.auth_token_file);
    let fixture_root = broker.runtime_root.join("runtime");
    fs::create_dir_all(&fixture_root).unwrap();
    // Python is the portable test client, copied to a runtime basename recognized
    // by the resolver. Attribution still reads the real executable, argv and TCP
    // owner from procfs; the client cannot send a PID in an HTTP header.
    let executable = fixture_root.join("node");
    fs::copy(fs::canonicalize("/usr/bin/python3").unwrap(), &executable).unwrap();
    let daemon = fixture_root.join("daemon.js");
    let task = fixture_root.join("task.js");
    fs::write(&daemon, CLIENT_SCRIPT).unwrap();
    fs::write(&task, CLIENT_SCRIPT).unwrap();
    update_mitm_config(
        api_addr,
        &token,
        &json!({"tls_decryption": {
            "default_action": "intercept",
            "rules": [{"id":"daemon-entry", "action":"passthrough", "process_names":["node"], "process_entry_points":[daemon]}]
        }}),
    );

    for (script, runtime_option, outcome) in [
        (&daemon, None, "passthrough"),
        (&task, None, "intercepted"),
        // Python accepts -u; the Node/Electron parser must leave an unknown
        // runtime option unattributed rather than guessing the next argument.
        (&daemon, Some("-u"), "intercepted"),
    ] {
        let upstream = TlsUpstream::start(&broker.runtime_root);
        let child = Command::new(&executable)
            .args(runtime_option)
            .arg(script)
            .arg(proxy.port().to_string())
            .arg(upstream.port.to_string())
            .arg(broker.runtime_root.join("upstream.pem"))
            .arg("argument-not-for-diagnostics")
            .env("ABYSS_TEST_SECRET", "environment-not-for-diagnostics")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let pid = child.id();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "client failed: {}\n{}",
            String::from_utf8_lossy(&output.stderr),
            broker.read_log()
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            outcome,
            "{}",
            broker.read_log()
        );
        upstream.thread.join().unwrap();

        let deadline = Instant::now().checked_add(REST_TIMEOUT).unwrap();
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
                .find(|flow| flow["source_process"]["pid"] == pid)
            {
                if runtime_option.is_some() {
                    assert!(flow["source_process"]["entry_point"].is_null());
                } else {
                    assert_eq!(
                        flow["source_process"]["entry_point"],
                        script.to_str().unwrap()
                    );
                }
                assert_eq!(flow["source_process"]["name"], "node");
                assert_eq!(flow["decision"] == "passthrough", outcome == "passthrough");
                let serialized = diagnostics.to_string();
                assert!(!serialized.contains("argument-not-for-diagnostics"));
                assert!(!serialized.contains("environment-not-for-diagnostics"));
                break;
            }
            assert!(
                Instant::now() < deadline,
                "missing Linux process attribution: {}",
                broker.read_log()
            );
            thread::sleep(super::POLL_INTERVAL);
        }
    }
    broker.shutdown();
    broker.wait_for_exit();
}

struct TlsUpstream {
    port: u16,
    thread: thread::JoinHandle<()>,
}

impl TlsUpstream {
    fn start(root: &Path) -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        fs::write(root.join("upstream.pem"), certified.cert.pem()).unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![certified.cert.der().clone()],
                PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der()).into(),
            )
            .unwrap();
        let listener = TcpListener::bind(loopback_ephemeral_addr()).unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let thread = thread::spawn(move || {
            let deadline = Instant::now().checked_add(REST_TIMEOUT).unwrap();
            let socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "upstream was never connected");
                        thread::sleep(super::POLL_INTERVAL);
                    }
                    Err(error) => panic!("upstream failed: {error}"),
                }
            };
            socket.set_nonblocking(false).unwrap();
            socket.set_read_timeout(Some(REST_TIMEOUT)).unwrap();
            socket.set_write_timeout(Some(REST_TIMEOUT)).unwrap();
            let mut tls =
                StreamOwned::new(ServerConnection::new(Arc::new(config)).unwrap(), socket);
            let mut request = [0_u8; 2048];
            if let Ok(size) = tls.read(&mut request) {
                if !request[..size].starts_with(b"GET /opaque ") {
                    return;
                }
                tls.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .unwrap();
                tls.conn.send_close_notify();
                drop(tls.flush());
            }
        });
        Self { port, thread }
    }
}
