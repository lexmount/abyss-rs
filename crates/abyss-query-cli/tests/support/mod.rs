//! External HTTP fixture and isolated CLI process harness.

use serde_json::{Value, json};
use std::{
    io::{BufRead as _, BufReader, Read as _, Write as _},
    net::{TcpListener, TcpStream},
    process::{Command, Output},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

pub const ID: &str = "11111111-1111-4111-8111-111111111111";
pub const TOKEN: &str = "fixture-secret-never-print";

pub struct Response {
    pub status: u16,
    pub body: String,
    pub headers: Vec<(String, String)>,
}
impl Response {
    pub fn json(body: &Value) -> Self {
        Self {
            status: 200_u16,
            body: body.to_string(),
            headers: Vec::new(),
        }
    }
    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: TOKEN.into(),
            headers: Vec::new(),
        }
    }
}
pub struct Request {
    pub target: String,
    pub authorization: Option<String>,
    pub body: Value,
}
pub struct Server {
    pub endpoint: String,
    requests: mpsc::Receiver<Request>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    pub fn start(responses: Vec<Response>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        listener.set_nonblocking(true).expect("nonblocking fixture");
        let endpoint = format!(
            "http://{}/prefix/",
            listener.local_addr().expect("fixture address")
        );
        let (sender, requests) = mpsc::channel();
        let worker = thread::spawn(move || {
            for response in responses {
                let deadline = Instant::now()
                    .checked_add(Duration::from_secs(15))
                    .expect("deadline");
                let mut stream = loop {
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && Instant::now() < deadline =>
                        {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("fixture accept: {error}"),
                    }
                };
                stream
                    .set_nonblocking(false)
                    .expect("blocking accepted socket");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                let request = Self::read(&mut stream);
                sender.send(request).expect("capture request");
                write!(stream, "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n", response.status, response.body.len()).expect("headers");
                for (name, value) in response.headers {
                    write!(stream, "{name}: {value}\r\n").expect("custom header");
                }
                write!(stream, "\r\n{}", response.body).expect("response body");
            }
        });
        Self {
            endpoint,
            requests,
            worker: Some(worker),
        }
    }
    fn read(stream: &mut TcpStream) -> Request {
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).expect("request line");
        let target = line.split_whitespace().nth(1).expect("target").to_owned();
        let mut authorization = None;
        let mut length = 0_usize;
        loop {
            line.clear();
            assert!(
                reader.read_line(&mut line).expect("request header") > 0,
                "request ended before its headers"
            );
            if line == "\r\n" {
                break;
            }
            let (name, value) = line.split_once(':').expect("header field");
            if name.eq_ignore_ascii_case("authorization") {
                authorization = Some(value.trim().into());
            }
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse().expect("body length");
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).expect("request body");
        Request {
            target,
            authorization,
            body: if body.is_empty() {
                Value::Null
            } else {
                serde_json::from_slice(&body).expect("JSON body")
            },
        }
    }
    pub fn finish(mut self) -> Vec<Request> {
        self.worker
            .take()
            .expect("worker")
            .join()
            .expect("fixture completed");
        self.requests.try_iter().collect()
    }
}

pub struct Harness {
    pub directory: tempfile::TempDir,
}
impl Harness {
    pub fn new() -> Self {
        Self {
            directory: tempfile::tempdir().expect("isolated directory"),
        }
    }
    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_abyss-query"));
        command
            .args(["--config"])
            .arg(self.directory.path().join("profiles.json"));
        command
            .env_remove("ABYSS_QUERY_PROFILE")
            .env_remove("ABYSS_QUERY_CONFIG")
            .env("QUERY_TEST_TOKEN", TOKEN);
        command
    }
    pub fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().expect("execute CLI")
    }
    pub fn success(&self, args: &[&str]) -> Value {
        let output = self.run(args);
        assert!(
            output.status.success(),
            "CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("JSON output")
    }
    pub fn profile(&self, endpoint: &str, auth: &str) {
        let mut args = vec![
            "profile",
            "add",
            "test",
            "--endpoint",
            endpoint,
            "--auth",
            auth,
            "--retries",
            "0",
        ];
        if auth == "bearer" {
            args.extend(["--token-env", "QUERY_TEST_TOKEN"]);
        }
        self.success(&args);
    }
}
pub fn session() -> Value {
    json!({"session_pk":ID,"session_id":"native-session","agent_name":"codex","started_at":"2026-01-01T00:00:00Z","title":null,"future_field":{"retained":true}})
}
pub fn sessions(page: u32, size: u32, more: bool) -> Value {
    json!({"total_sessions":2_u32,"page":page,"page_size":size,"has_more":more,"items":[session()]})
}
pub fn event() -> Value {
    json!({"id":ID,"event_id":"source-event","session_pk":ID,"conversation":{"entries":[{"role":"user","text":"hello"}],"completeness":"partial"},"metadata":{"partial":true}})
}
