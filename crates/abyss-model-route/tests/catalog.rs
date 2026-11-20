//! Exercise the worker's HTTP management and broker inspection protocols.

mod support;
use serde_json::{Value, json};
use std::{fs, process::Command};
use tempfile::tempdir;

#[test]
fn executable_only_accepts_service_startup() {
    let output = Command::new(env!("CARGO_BIN_EXE_abyss-model-route"))
        .arg("select")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "management operations belong to HTTP"
    );
    let dir = tempdir().unwrap();
    let file = dir.path().join("startup.json");
    fs::write(&file, "{}").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_abyss-model-route"))
        .arg("--serve")
        .arg(file)
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&output.stderr).trim(),
        "Invalid broker startup information."
    );
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
fn selections_survive_host_restarts_and_clear_when_the_source_changes() {
    let dir = tempdir().unwrap();
    let profile = dir.path().join("profile.json");
    let worker = support::Worker::start(&profile);
    let load = |name: &str| json!({"source":name,"catalog":catalog()});
    let (status, imported) = worker.request("PUT", "/catalog", &load("file A.json"));
    assert_eq!(status, 200);
    assert!(
        !imported.to_string().contains("fixture-api-key"),
        "user-facing status redacts credentials"
    );
    assert_eq!(
        worker.request("GET", "/profile", &Value::Null).0,
        404,
        "private credentials stay at the worker"
    );
    let models = json!({"provider":"relay", "credential":"primary"});
    assert_eq!(
        worker.request("POST", "/models", &models),
        (200, json!(["model-a"]))
    );
    let select = |credential: &str| {
        worker.request("PUT", "/selection", &json!({
        "harness":"codex","selection":{"provider":"relay","credential":credential,"model":"model-a"}
    })).0
    };
    assert_eq!(select("subscriber"), 400);
    assert_eq!(select("primary"), 200);
    assert_eq!(
        worker.inspect("explicit_proxy", None)["decision"]["action"],
        "allow"
    );
    let source_pid = Some(std::process::id());
    let decision = worker.inspect("macos_network_extension", source_pid);
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
        worker.inspect("macos_network_extension", source_pid),
        decision,
        "the worker serves an accepted snapshot from memory"
    );
    fs::rename(hidden, durable).unwrap();
    drop(worker);
    let restarted = support::Worker::start(&profile);
    let (status, state) = restarted.request("GET", "", &Value::Null);
    assert_eq!(status, 200);
    assert_eq!(state["selections"]["codex"]["credential"], "primary");
    let (_, changed) = restarted.request("PUT", "/catalog", &load("file B.json"));
    assert_eq!(changed["selections"], json!({}));
}
