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
        "harness_providers": {"codex": ["relay", "openai"], "deepseek-harness": ["relay"], "claude-code": ["anthropic"]},
        "providers": {
            "anthropic": {"credentials":{"team":{"kind":"api_key","api_key":"fixture-team"}}},
            "relay": {
                "base_url": "https://relay.example/custom/v1",
                "credentials": {
                    "primary": {"kind":"api_key", "api_key":"fixture-api-key"},
                    "subscriber":{"kind":"account", "login":"fixture-login", "secret":"fixture-secret"}
                },
                "models":["model-a"]
            }
        }
    })
}

#[test]
fn selections_survive_restarts_and_follow_the_catalog_contents() {
    let dir = tempdir().unwrap();
    let profile = dir.path().join("profile.json");
    let worker = support::Worker::start(&profile);
    let saved = json!({"source":"old.json","catalog":catalog(),"selections":{}});
    assert_eq!(worker.request("PUT", "/profile", &saved).0, 404);
    assert_eq!(
        worker.request("GET", "", &Value::Null).1["catalog"]["providers"],
        json!({})
    );
    let (status, imported) = worker.request("PUT", "/catalog", &catalog());
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
    let persisted: Value = serde_json::from_slice(&fs::read(&durable).unwrap()).unwrap();
    assert!(persisted.get("source").is_none());
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
    assert!(state.get("source").is_none());
    assert_eq!(
        restarted.request("PUT", "/catalog", &catalog()),
        (200, state.clone())
    );

    let selection = json!({"harness":"codex","selection":state["selections"]["codex"]});
    let independent = json!({"provider":"anthropic","credential":"team","model":"model-b"});
    assert_eq!(
        restarted
            .request(
                "PUT",
                "/selection",
                &json!({"harness":"claude-code","selection":independent})
            )
            .0,
        200
    );
    let mut no_credential = catalog();
    no_credential["providers"]["relay"]["credentials"]
        .as_object_mut()
        .unwrap()
        .remove("primary");
    let mut no_provider = catalog();
    no_provider["providers"]
        .as_object_mut()
        .unwrap()
        .remove("relay");
    let mut moved = catalog();
    moved["providers"]["relay"]["base_url"] = json!("https://another.example/v1");
    for replacement in [no_credential, no_provider, moved] {
        let (status, changed) = restarted.request("PUT", "/catalog", &replacement);
        assert_eq!(status, 200);
        assert_eq!(changed["selections"], json!({"claude-code":independent}));
        assert_eq!(restarted.request("PUT", "/catalog", &catalog()).0, 200);
        assert_eq!(restarted.request("PUT", "/selection", &selection).0, 200);
    }
}

#[test]
fn selected_account_delivers_its_own_proxy_and_redacts_both_secrets() {
    let dir = tempdir().unwrap();
    let worker = support::Worker::start(&dir.path().join("profile.json"));
    let mut input = catalog();
    input["harness_providers"]["codex"] = json!(["anthropic"]);
    let credentials = &mut input["providers"]["anthropic"]["credentials"];
    credentials["password"] = json!({"kind":"account","login":"user","secret":"fixture-password"});
    for (id, port) in [("one", 1081_u16), ("two", 1082_u16)] {
        credentials[id] = json!({
            "kind":"account", "login":id, "secret":format!("sk-ant-oat01-fixture-{id}"),
            "proxy":{"protocol":"socks5","host":"127.0.0.1","port":port,"username":id,"password":"proxy-secret"}
        });
    }
    let (status, state) = worker.request("PUT", "/catalog", &input);
    assert_eq!(status, 200);
    assert!(!state.to_string().contains("proxy-secret"));
    assert!(!state.to_string().contains("sk-ant-oat"));
    assert_eq!(
        state["catalog"]["providers"]["anthropic"]["credentials"]["password"]["configured"],
        false
    );
    for (id, port) in [("one", 1081_u16), ("two", 1082_u16)] {
        assert_eq!(
            state["catalog"]["providers"]["anthropic"]["credentials"][id],
            json!({"kind":"account","configured":true})
        );
        let choice = json!({"harness":"codex","selection":{"provider":"anthropic","credential":id,"model":"model-a"}});
        assert_eq!(worker.request("PUT", "/selection", &choice).0, 200);
        let decision = worker.inspect("explicit_proxy", Some(std::process::id()));
        let actions = decision["decision"]["actions"].as_array().unwrap();
        assert!(
            actions
                .iter()
                .any(|a| a["op"] == "set_upstream_proxy" && a["value"]["port"] == port)
        );
        assert!(actions.iter().any(|a| a["op"] == "set_auth_token"
            && a["scheme"] == "bearer"
            && a["value"] == format!("sk-ant-oat01-fixture-{id}")));
    }
}
