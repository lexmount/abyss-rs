//! Broker protocol peer for executable-level routing control regression tests.

use http_body_util::BodyExt as _;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub struct Worker {
    child: Child,
    control: PathBuf,
    requests: tokio::sync::mpsc::UnboundedSender<(Value, mpsc::Sender<Value>)>,
}

impl Worker {
    pub fn start(profile: &Path) -> Self {
        let directory = profile.parent().unwrap();
        let startup = directory.join("broker.json");
        let (endpoint_tx, endpoint_rx) = mpsc::channel();
        let (requests, mut receive) =
            tokio::sync::mpsc::unbounded_channel::<(Value, mpsc::Sender<Value>)>();
        let socket_path = directory.join("broker.sock");
        thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut stream = accept(socket_path, endpoint_tx).await;
                let hello = read(&mut stream).await;
                assert_eq!(
                    hello["plugin_id"], "abyss.model-route",
                    "worker identifies its inspection session"
                );
                write(
                    &mut stream,
                    &json!({"type":"broker_hello","protocol_version":1_u8}),
                )
                .await;
                while let Some((request, response)) = receive.recv().await {
                    write(&mut stream, &request).await;
                    response.send(read(&mut stream).await).unwrap();
                }
            });
        });
        let endpoint = endpoint_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        fs::write(
            &startup,
            json!({"pid":std::process::id(),"plugin_endpoint":endpoint}).to_string(),
        )
        .unwrap();
        #[cfg(unix)]
        let control = directory.join("control.sock");
        #[cfg(windows)]
        let control = {
            use sha2::{Digest as _, Sha256};
            let key = Sha256::digest(profile.as_os_str().as_encoded_bytes());
            PathBuf::from(format!(r"\\.\pipe\abyss-route-control-{key:x}"))
        };
        let mut child = Command::new(env!("CARGO_BIN_EXE_abyss-model-route"))
            .arg("--control")
            .arg(&control)
            .arg("--profile")
            .arg(profile)
            .arg("--serve")
            .arg(startup)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let started = Instant::now();
        loop {
            if request(&control, "GET", "/status", &Value::Null).is_some() {
                break;
            }
            assert!(
                child.try_wait().unwrap().is_none(),
                "worker should stay connected"
            );
            assert!(
                started.elapsed() < Duration::from_secs(8),
                "REST endpoint should become ready"
            );
            thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            control,
            requests,
        }
    }

    pub fn request(&self, method: &str, resource: &str, body: &Value) -> (u16, Value) {
        request(&self.control, method, resource, body).unwrap()
    }

    pub fn inspect(&self, ingress: &str, source_pid: Option<u32>) -> Value {
        let mut request: Value = serde_json::from_str(include_str!(
            "../../../../specs/broker-plugin-protocol/v1/fixtures/inspect-request.json"
        ))
        .unwrap();
        request["context"]["ingress"] = json!(ingress);
        if let Some(pid) = source_pid {
            request["context"]["source_process"] = json!({"pid": pid});
        }
        request["context"]["harness"] = json!({"id":"codex"});
        let (tx, rx) = mpsc::channel();
        self.requests.send((request, tx)).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _killed = self.child.kill();
        let _status = self.child.wait();
    }
}

#[cfg(unix)]
async fn accept(path: PathBuf, ready: mpsc::Sender<String>) -> tokio::net::UnixStream {
    if path.exists() {
        fs::remove_file(&path).unwrap();
    }
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    ready.send(path.display().to_string()).unwrap();
    listener.accept().await.unwrap().0
}

#[cfg(windows)]
async fn accept(
    path: PathBuf,
    ready: mpsc::Sender<String>,
) -> tokio::net::windows::named_pipe::NamedPipeServer {
    use sha2::{Digest as _, Sha256};
    let digest = Sha256::digest(path.as_os_str().as_encoded_bytes());
    let name = format!(r"\\.\pipe\abyss-route-test-{digest:x}");
    let listener = tokio::net::windows::named_pipe::ServerOptions::new()
        .first_pipe_instance(true)
        .create(&name)
        .unwrap();
    ready.send(name).unwrap();
    listener.connect().await.unwrap();
    listener
}

async fn read<S: AsyncRead + Unpin>(stream: &mut S) -> Value {
    let n = stream.read_u32().await.unwrap();
    let mut data = vec![0; usize::try_from(n).unwrap()];
    stream.read_exact(&mut data).await.unwrap();
    serde_json::from_slice(&data).unwrap()
}

async fn write<S: AsyncWrite + Unpin>(stream: &mut S, value: &Value) {
    let data = serde_json::to_vec(value).unwrap();
    stream
        .write_u32(u32::try_from(data.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(&data).await.unwrap();
}

fn request(path: &Path, method: &str, resource: &str, body: &Value) -> Option<(u16, Value)> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        #[cfg(unix)]
        let stream = tokio::net::UnixStream::connect(path).await.ok()?;
        #[cfg(windows)]
        let stream = tokio::net::windows::named_pipe::ClientOptions::new()
            .open(path)
            .ok()?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
                .await
                .ok()?;
        tokio::spawn(connection);
        let request = hyper::Request::builder()
            .method(method)
            .uri(format!("/v1/model-route{resource}"))
            .header("host", "localhost")
            .body(http_body_util::Full::new(bytes::Bytes::from(
                serde_json::to_vec(body).unwrap(),
            )))
            .unwrap();
        let response = sender.send_request(request).await.ok()?;
        let status = response.status().as_u16();
        let bytes = response.into_body().collect().await.ok()?.to_bytes();
        Some((status, serde_json::from_slice(&bytes).unwrap()))
    })
}
