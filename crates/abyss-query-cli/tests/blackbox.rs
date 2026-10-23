//! Real-process contract tests against an external HTTP listener.

mod support;
use serde_json::{Value, json};
use support::{Harness, ID, Response, Server, TOKEN, event, session, sessions};

#[test]
fn profiles_are_persistent_and_do_not_contain_credentials() {
    let cli = Harness::new();
    cli.profile("https://example.test/api", "bearer");
    let show = cli.success(&["profile", "show"]);
    assert_eq!(
        show["data"]["endpoint"], "https://example.test/api/",
        "normalize prefix"
    );
    let config =
        std::fs::read_to_string(cli.directory.path().join("profiles.json")).expect("config");
    assert!(
        !config.contains(TOKEN),
        "profile must contain only a token reference"
    );
    cli.success(&[
        "profile",
        "add",
        "anonymous",
        "--endpoint",
        "http://localhost:9999",
        "--auth",
        "none",
    ]);
    cli.success(&["profile", "use", "anonymous"]);
    assert_eq!(
        cli.success(&["auth", "status"])["data"]["mode"],
        "none",
        "active profile persisted"
    );
    cli.success(&["profile", "remove", "test"]);
    assert_eq!(
        cli.success(&["profile", "list"])["data"]["profiles"]
            .as_object()
            .expect("profiles")
            .len(),
        1,
        "remove profile"
    );
}

#[test]
fn anonymous_mode_preserves_prefix_and_repeated_encoded_filters() {
    let server = Server::start(vec![Response::json(&sessions(1, 20, false))]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "none");
    let output = cli.success(&[
        "sessions",
        "list",
        "--agent",
        "a&b",
        "--agent",
        "另一个",
        "--model",
        "model/one",
    ]);
    assert_eq!(
        output["data"][0]["future_field"]["retained"], true,
        "unknown metadata preserved"
    );
    let requests = server.finish();
    assert!(
        requests[0].body.is_null(),
        "GET must not send a request body"
    );
    assert!(
        requests[0].authorization.is_none(),
        "anonymous mode ignores available token env"
    );
    assert!(
        requests[0]
            .target
            .starts_with("/prefix/v1/agent-usage/sessions?"),
        "retain API prefix"
    );
    let url = reqwest::Url::parse(&format!("http://localhost{}", requests[0].target))
        .expect("request URL");
    assert_eq!(
        url.query_pairs()
            .filter(|(key, _)| key == "agent_name")
            .count(),
        2,
        "repeat exact filters"
    );
    assert!(
        url.query_pairs()
            .any(|(key, value)| key == "agent_name" && value == "a&b"),
        "escape query delimiters"
    );
}

#[test]
fn session_pagination_is_bounded_and_resumable() {
    let server = Server::start(vec![
        Response::json(&sessions(1, 1, true)),
        Response::json(&sessions(2, 1, true)),
    ]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "bearer");
    let output = cli.success(&[
        "sessions",
        "list",
        "--all",
        "--page-size",
        "1",
        "--max-items",
        "2",
    ]);
    assert_eq!(
        output["data"].as_array().expect("items").len(),
        2,
        "item budget"
    );
    assert_eq!(
        output["meta"]["next"],
        json!({"page":3_u32,"page_size":1_u32}),
        "resumable window"
    );
    assert_eq!(output["meta"]["truncated"], true, "report bound");
    let requests = server.finish();
    assert_eq!(
        requests[0].authorization.as_deref(),
        Some(format!("Bearer {TOKEN}").as_str()),
        "bearer header"
    );
    assert!(requests[1].target.contains("page=2"), "advance page");
}

#[test]
fn events_follow_decimal_offsets_and_reject_cycles() {
    let server = Server::start(vec![
        Response::json(&json!({"events":[event()],"next_page_token":"7"})),
        Response::json(&json!({"events":[event()],"next_page_token":null})),
    ]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "none");
    let output = cli.success(&["events", "list", "--all", "--full", "--session-pk", ID]);
    assert_eq!(output["meta"]["pages"], 2_u32, "follow event continuation");
    assert_eq!(
        output["data"][0]["metadata"]["partial"], true,
        "partial content metadata preserved"
    );
    assert!(
        server.finish()[1].target.contains("offset=7"),
        "backend token is a decimal offset"
    );
    let server = Server::start(vec![Response::json(
        &json!({"events":[event()],"next_page_token":"0"}),
    )]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "none");
    let output = cli.run(&["events", "list", "--all"]);
    assert_eq!(
        output.status.code(),
        Some(9_i32),
        "reject non-advancing token"
    );
    assert!(output.stdout.is_empty(), "no partial success output");
    server.finish();
}

#[test]
fn detail_search_and_summary_routes_preserve_backend_content() {
    let timeline = json!({"session":session(),"turns":[{"turn_pk":ID,"turn_index":1_u32,"events":[{"preview":"content","text_chars":7_u32}]}]});
    let trajectory = json!({"session":session(),"items":[{"kind":"tool_call","input":{"command":"hello"}}],"events":[]});
    let mut hit = session();
    hit["matches"] = json!([{"segments":[{"text":"hello","highlight":true}]}]);
    let search = json!({"query":"hello","total_sessions":1_u32,"page":1_u32,"page_size":20_u32,"has_more":false,"items":[hit]});
    let summary = json!({"group_by":["agent_name"],"rows":[{"agent_name":"codex","input_tokens":10_u32}],"next_page_token":null});
    let server = Server::start(vec![
        Response::json(&timeline),
        Response::json(&timeline),
        Response::json(&trajectory),
        Response::json(&event()),
        Response::json(&search),
        Response::json(&summary),
    ]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "none");
    cli.success(&["sessions", "get", ID]);
    assert!(
        cli.success(&["sessions", "outline", ID])["data"]["turns"][0]["events"][0]
            .get("text")
            .is_none(),
        "outline does not invent full content"
    );
    assert_eq!(
        cli.success(&["sessions", "trajectory", ID])["data"]["items"][0]["kind"],
        "tool_call",
        "trajectory preserved"
    );
    cli.success(&["events", "get", ID]);
    assert_eq!(
        cli.success(&["search", "hello"])["data"][0]["matches"][0]["segments"][0]["highlight"],
        true,
        "structured search highlights preserved"
    );
    cli.success(&["usage", "summary", "--group-by", "agent_name", "--global"]);
    let requests = server.finish();
    assert!(requests[1].target.ends_with("/outline"), "outline route");
    assert!(
        requests[2].target.ends_with("/trajectory"),
        "trajectory route"
    );
    assert!(
        requests[5].target.contains("scope=global"),
        "explicit scope"
    );
}

#[test]
fn errors_are_stable_sanitized_and_never_downgrade_authentication() {
    for (status, code) in [
        (401, 3_i32),
        (403, 4_i32),
        (404, 5_i32),
        (429, 6_i32),
        (503, 8_i32),
    ] {
        let server = Server::start(vec![Response::status(status)]);
        let cli = Harness::new();
        cli.profile(&server.endpoint, "bearer");
        let output = cli.run(&["doctor"]);
        assert_eq!(
            output.status.code(),
            Some(code),
            "stable status mapping for {status}"
        );
        assert!(output.stdout.is_empty(), "errors only on stderr");
        let error: Value = serde_json::from_slice(&output.stderr).expect("structured error");
        assert_eq!(error["error"]["http_status"], status, "status retained");
        assert!(
            !String::from_utf8_lossy(&output.stderr).contains(TOKEN),
            "never reflect error body or credential"
        );
        assert_eq!(
            server.finish().len(),
            1,
            "never retry with anonymous credentials"
        );
    }
}

#[test]
fn redirects_are_not_followed_and_json_errors_are_sanitized() {
    let mut redirect = Response::status(302);
    redirect
        .headers
        .push(("Location".into(), format!("http://127.0.0.1:1/{TOKEN}")));
    let server = Server::start(vec![
        redirect,
        Response {
            status: 200_u16,
            body: TOKEN.into(),
            headers: Vec::new(),
        },
    ]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "bearer");
    assert_eq!(
        cli.run(&["doctor"]).status.code(),
        Some(8_i32),
        "do not follow redirect"
    );
    let invalid = cli.run(&["doctor"]);
    assert_eq!(
        invalid.status.code(),
        Some(9_i32),
        "invalid JSON is protocol error"
    );
    assert!(
        !String::from_utf8_lossy(&invalid.stderr).contains(TOKEN),
        "decode errors redact content"
    );
    server.finish();
}

#[test]
fn formats_and_schema_work_without_interactive_queries() {
    let server = Server::start(vec![
        Response::json(&sessions(1, 20, false)),
        Response::json(&sessions(1, 20, false)),
    ]);
    let cli = Harness::new();
    cli.profile(&server.endpoint, "none");
    let jsonl = cli.run(&["--format", "jsonl", "sessions", "list"]);
    assert!(jsonl.status.success(), "JSONL success");
    let lines: Vec<Value> = String::from_utf8(jsonl.stdout)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("JSONL record"))
        .collect();
    assert!(
        lines[0].get("record").is_some() && lines[1].get("meta").is_some(),
        "records and final metadata"
    );
    let table = cli.run(&["--format", "table", "sessions", "list"]);
    assert!(
        String::from_utf8_lossy(&table.stdout).starts_with("ID\tAGENT\t"),
        "table headers"
    );
    server.finish();
    let clean = Harness::new();
    assert!(
        clean.success(&["schema"])["data"]["event_page"]
            .get("$schema")
            .is_some(),
        "offline schema"
    );
    let invalid = clean.run(&["sessions", "get", TOKEN]);
    assert_eq!(invalid.status.code(), Some(2_i32), "invalid arguments");
    assert!(
        !String::from_utf8_lossy(&invalid.stderr).contains(TOKEN),
        "argument errors do not echo secrets"
    );
}

#[test]
fn token_files_and_header_files_support_local_deployments() {
    for header in [false, true] {
        let server = Server::start(vec![Response::json(&sessions(1, 1, false))]);
        let cli = Harness::new();
        let path = cli.directory.path().join("token");
        std::fs::write(
            &path,
            if header {
                format!("Authorization: Bearer {TOKEN}\n")
            } else {
                format!("{TOKEN}\n")
            },
        )
        .expect("credential fixture");
        cli.success(&[
            "profile",
            "add",
            "test",
            "--endpoint",
            &server.endpoint,
            "--auth",
            "bearer",
            if header {
                "--header-file"
            } else {
                "--token-file"
            },
            path.to_str().expect("path"),
        ]);
        cli.success(&["doctor"]);
        assert!(
            server.finish()[0].authorization.is_some(),
            "file credential sent"
        );
    }
}

#[cfg(unix)]
#[test]
fn terminal_login_pkce_persists_bound_private_credentials_and_revokes() {
    use std::os::unix::fs::PermissionsExt as _;
    let server = Server::start(vec![
        Response::json(
            &json!({"attempt_id":ID,"poll_token":"poll-secret","verification_url":"https://example.test/login?code=123","expires_at":"2099-01-01T00:00:00Z","poll_interval_seconds":1_u32}),
        ),
        Response::json(&json!({"status":"completed"})),
        Response::json(
            &json!({"token":TOKEN,"expires_at":"2099-01-01T00:00:00Z","user":{"id":ID,"email":"fixture@example.test","name":null,"roles":[]}}),
        ),
        Response::json(&sessions(1, 1, false)),
        Response::json(&json!({"ok":true})),
    ]);
    let cli = Harness::new();
    cli.success(&[
        "profile",
        "add",
        "test",
        "--endpoint",
        &server.endpoint,
        "--auth",
        "terminal",
        "--auth-endpoint",
        &server.endpoint,
        "--credential-store",
        "file",
    ]);
    let login = cli.run(&["auth", "login"]);
    assert!(
        login.status.success(),
        "login: {}",
        String::from_utf8_lossy(&login.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&login.stdout).contains(TOKEN),
        "login redacts bearer"
    );
    let credential = std::fs::read_dir(cli.directory.path().join("credentials"))
        .expect("credentials")
        .next()
        .expect("entry")
        .expect("entry")
        .path();
    assert_eq!(
        std::fs::metadata(&credential)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o077,
        0,
        "private credential permissions"
    );
    cli.success(&["auth", "status"]);
    cli.success(&["doctor"]);
    cli.success(&["auth", "logout"]);
    assert!(!credential.exists(), "revoke then delete");
    let requests = server.finish();
    assert_eq!(
        requests[0].body["state"], requests[2].body["state"],
        "PKCE state roundtrip"
    );
    let verifier = requests[2].body["code_verifier"]
        .as_str()
        .expect("verifier");
    assert_eq!(
        abyss_terminal_auth::pkce::code_challenge_for_verifier(verifier),
        requests[0].body["code_challenge"],
        "PKCE challenge matches"
    );
    assert!(
        requests[3].authorization.is_some() && requests[4].authorization.is_some(),
        "read and revocation use stored bearer"
    );
}
