//! Exercise the executable boundary used by both native hosts.

mod support;

use std::{
    fs,
    io::Write as _,
    process::{Command, Output, Stdio},
};

use serde_json::{Value, json};
use tempfile::tempdir;

fn run(args: &[&str], input: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_abyss-model-route"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn worker_invocations_read_the_supplied_startup_file() {
    let directory = tempdir().unwrap();
    fs::write(directory.path().join("startup.json"), b"{}").unwrap();
    let check = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_abyss-model-route"))
            .current_dir(directory.path())
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "the broker endpoint is missing");
        assert_eq!(
            String::from_utf8(output.stderr).unwrap().trim(),
            "Invalid broker startup information.",
            "{args:?} should reach the routing worker"
        );
    };
    check(&["--serve", "startup.json"]);
    #[cfg(unix)]
    check(&["--profile", "state", "serve", "startup.json"]);
}

fn catalog() -> Value {
    json!({
        "harness_providers": {"codex": ["relay", "openai"], "deepseek-harness": ["relay"], "claude-code": []},
        "providers": {"relay": {
            "base_url": "https://relay.example/custom/v1",
            "credentials": {
                "primary": {"kind":"api_key", "api_key":"fixture-api-key"},
                "subscriber":{"kind":"account", "login":"fixture-login", "secret":"fixture-secret"}
            },
            "models":["model-a"]
        }}
    })
}

#[test]
fn json_file_and_native_picker_return_identical_choices() {
    let directory = tempdir().unwrap();
    let path = directory.path().join("model-route.json");
    fs::write(&path, catalog().to_string()).unwrap();
    let expected = json!({
        "harness_providers": {"codex": ["relay"], "deepseek-harness": ["relay"], "claude-code":[]},
        "providers":{"relay":{"base_url":"https://relay.example/custom/v1","credentials":{"primary":{"kind":"api_key","configured":true},"subscriber":{"kind":"account","configured":false}},"models":["model-a"]}}
    });
    for output in [
        run(&["--catalog-stdin"], &catalog()),
        run(&[], &json!({"source":{"type":"file","path":path}})),
    ] {
        assert!(output.status.success(), "catalog should be readable");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            expected,
            "only public metadata may reach the UI"
        );
        assert!(output.stderr.is_empty(), "successful catalog read is quiet");
    }
    let other = directory.path().join("models.txt");
    fs::write(&other, catalog().to_string()).unwrap();
    for invalid in [directory.path(), other.as_path()] {
        let output = run(&[], &json!({"source":{"type":"file","path":invalid}}));
        assert!(!output.status.success());
    }
    let profile = directory.path().join("profile.json");
    assert!(
        !run(
            &["--profile", profile.to_str().unwrap(), "file", "models.txt"],
            &catalog()
        )
        .status
        .success()
    );
}

#[test]
fn management_bearer_stays_with_the_issuing_origin() {
    let result = run(
        &[],
        &json!({
            "source":{"type":"service","url":"https://unrelated.invalid/config","sso":true},
            "session":{"origin":"https://company.invalid","bearer":"test-bearer"}
        }),
    );
    assert!(
        !result.status.success(),
        "mismatch should reject before the request"
    );
    assert_eq!(
        String::from_utf8(result.stderr).unwrap().trim(),
        "Configuration service must share the SSO origin."
    );
}

#[test]
fn selections_survive_host_restarts_and_clear_when_the_source_changes() {
    let dir = tempdir().unwrap();
    let profile = dir.path().join("profile.json");
    let worker = support::Worker::start(&profile);
    let path = profile.to_str().unwrap();
    let select = |credential: &str| {
        run(
            &["--profile", path, "select"],
            &json!({"harness":"codex","selection":{"provider":"relay","credential":credential,"model":"model-a"}}),
        )
    };
    assert!(
        run(&["--profile", path, "file", "file A.json"], &catalog())
            .status
            .success()
    );
    assert!(
        !select("subscriber").status.success(),
        "provider account login requires a provider-specific sign-in flow"
    );
    assert!(select("primary").status.success());
    assert_eq!(
        worker.inspect("explicit_proxy")["decision"]["action"],
        "allow"
    );
    let decision = worker.inspect("owned_explicit_proxy");
    assert_eq!(decision["decision"]["action"], "modify");
    let state_dir = profile.with_extension("routes");
    let durable = fs::read_dir(&state_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|p| p.extension().is_some_and(|e| e == "json"))
        .unwrap();
    let hidden = durable.with_extension("held");
    fs::rename(&durable, &hidden).unwrap();
    assert_eq!(
        worker.inspect("owned_explicit_proxy"),
        decision,
        "the worker serves an accepted snapshot from memory"
    );
    fs::rename(hidden, durable).unwrap();
    drop(worker);
    let _restarted = support::Worker::start(&profile);
    let snapshot = run(&["--profile", path, "state"], &Value::Null);
    let state: Value = serde_json::from_slice(&snapshot.stdout).unwrap();
    assert_eq!(state["selections"]["codex"]["credential"], "primary");
    assert!(
        !state.to_string().contains("fixture-api-key"),
        "no header values in UI snapshot"
    );
    let changed = run(&["--profile", path, "file", "file B.json"], &catalog());
    let state: Value = serde_json::from_slice(&changed.stdout).unwrap();
    assert_eq!(state["selections"], json!({}));
}

#[test]
fn management_service_uses_the_existing_session_only_when_selected() {
    use std::{
        io::{BufRead as _, BufReader},
        net::TcpListener,
        thread,
    };
    let server = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://{}", server.local_addr().unwrap());
    let serve = thread::spawn(move || {
        for authenticated in [false, true] {
            let (mut stream, _) = server.accept().unwrap();
            let head: Vec<_> = BufReader::new(&stream)
                .lines()
                .map(Result::unwrap)
                .take_while(|s| !s.is_empty())
                .collect();
            assert!(
                head[0].starts_with("GET /config?env=test "),
                "requested configuration path and query must survive"
            );
            assert_eq!(
                head.iter()
                    .any(|s| s.eq_ignore_ascii_case("authorization: Bearer fixture-SSO")),
                authenticated
            );
            let catalog = catalog().to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{catalog}",
                catalog.len()
            )
            .unwrap();
        }
    });
    let dir = tempdir().unwrap();
    let profile = dir.path().join("state.json");
    let _worker = support::Worker::start(&profile);
    for authenticated in [false, true] {
        let result = run(
            &["--profile", profile.to_str().unwrap(), "load"],
            &json!({
                "source":{"type":"service","url":format!("{origin}/config?env=test"),"sso":authenticated},
                "session":{"origin":origin,"bearer":"fixture-SSO"}
            }),
        );
        assert!(
            result.status.success(),
            "REST catalog acquisition should succeed"
        );
        let state: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(
            state["catalog"]["providers"]["relay"]["credentials"]["primary"]["configured"],
            true
        );
        assert!(
            !String::from_utf8(result.stdout)
                .unwrap()
                .contains("fixture-")
        );
    }
    serve.join().unwrap();
}
