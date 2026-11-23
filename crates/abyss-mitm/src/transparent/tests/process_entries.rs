//! Module selectors and real TLS regression coverage for shared Python interpreters.

use super::*;
use crate::{ModuleRuntime, ProcessEntry, TlsDecryptionContext};

fn policy() -> TlsDecryptionPolicy {
    serde_json::from_value(serde_json::json!({
        "default_action": "passthrough",
        "rules": [
            {"id":"hermes", "action":"intercept", "process_names":["python.exe", "pythonw.exe"],
             "process_entry_points":[{"kind":"module", "runtime":"python", "name":"hermes_cli.main"}], "destination_hosts":["api.openai.com"]},
            {"id":"python-fallback", "action":"passthrough", "process_names":["python.exe", "pythonw.exe"]},
            {"id":"other-clients", "action":"intercept", "destination_hosts":["api.openai.com"]}
        ]
    })).unwrap()
}

#[test]
fn one_entry_selector_matches_scripts_or_modules_and_rejects_old_shapes() {
    let script = ProcessEntry::script(
        std::env::temp_dir()
            .join("daemon.js")
            .to_str()
            .unwrap()
            .to_owned(),
    );
    let module = ProcessEntry::module(ModuleRuntime::Python, "agent.main".to_owned()).unwrap();
    let policy: TlsDecryptionPolicy = serde_json::from_value(serde_json::json!({
        "default_action":"passthrough",
        "rules":[{"id":"entries", "action":"intercept", "process_entry_points":[script, module]}]
    }))
    .unwrap();
    policy.validate().unwrap();
    for (entry, expected) in [
        (Some(script), TlsDecryptionAction::Intercept),
        (Some(module), TlsDecryptionAction::Intercept),
        (None, TlsDecryptionAction::Passthrough),
        (
            Some(ProcessEntry::module(ModuleRuntime::Python, "other.main".to_owned()).unwrap()),
            TlsDecryptionAction::Passthrough,
        ),
    ] {
        let source = SourceProcess::new(None, None, None).with_entry_point(entry);
        assert_eq!(
            policy
                .decide(TlsDecryptionContext::new(None, Some(&source)))
                .action(),
            expected
        );
    }
    for entry in [
        serde_json::json!("/opt/daemon.js"),
        serde_json::json!({"kind":"module", "name":"agent.main"}),
        serde_json::json!({"kind":"module", "runtime":"unknown", "name":"agent.main"}),
        serde_json::json!({"kind":"script", "path":"/opt/daemon.js", "name":"agent.main"}),
    ] {
        assert!(
            serde_json::from_value::<TlsDecryptionPolicy>(serde_json::json!({
                "rules":[{"id":"invalid", "action":"intercept", "process_entry_points":[entry]}]
            }))
            .is_err()
        );
    }
    assert!(
        serde_json::from_value::<TlsDecryptionPolicy>(serde_json::json!({
            "rules":[{"id":"old", "action":"intercept", "python_modules":["agent.main"]}]
        }))
        .is_err()
    );
}

#[test]
fn modules_are_exact_and_python_fallback_precedes_broad_host_rules() {
    let policy = policy();
    policy.validate().unwrap();
    for (name, module, host, action, rule) in [
        (
            "python.exe",
            Some("hermes_cli.main"),
            Some("api.openai.com"),
            TlsDecryptionAction::Intercept,
            Some("hermes"),
        ),
        (
            "pythonw.exe",
            Some("hermes_cli.main"),
            Some("api.openai.com"),
            TlsDecryptionAction::Intercept,
            Some("hermes"),
        ),
        (
            "python.exe",
            Some("hermes_cli.main.other"),
            Some("api.openai.com"),
            TlsDecryptionAction::Passthrough,
            Some("python-fallback"),
        ),
        (
            "python.exe",
            Some("Hermes_cli.main"),
            Some("api.openai.com"),
            TlsDecryptionAction::Passthrough,
            Some("python-fallback"),
        ),
        (
            "python.exe",
            Some("other"),
            Some("api.openai.com"),
            TlsDecryptionAction::Passthrough,
            Some("python-fallback"),
        ),
        (
            "python.exe",
            None,
            Some("api.openai.com"),
            TlsDecryptionAction::Passthrough,
            Some("python-fallback"),
        ),
        (
            "python.exe",
            Some("hermes_cli.main"),
            Some("unselected.test"),
            TlsDecryptionAction::Passthrough,
            Some("python-fallback"),
        ),
        (
            "python.exe",
            Some("hermes_cli.main"),
            None,
            TlsDecryptionAction::Passthrough,
            Some("python-fallback"),
        ),
        (
            "codex.exe",
            None,
            Some("api.openai.com"),
            TlsDecryptionAction::Intercept,
            Some("other-clients"),
        ),
    ] {
        let source =
            SourceProcess::new(Some(42), Some(name.to_owned()), None).with_entry_point(module.map(
                |value| ProcessEntry::module(ModuleRuntime::Python, value.to_owned()).unwrap(),
            ));
        let result = policy.decide(TlsDecryptionContext::new(host, Some(&source)));
        assert_eq!(
            (result.action(), result.matched_rule_id()),
            (action, rule),
            "{source:?}"
        );
    }
}

#[test]
fn invalid_modules_are_rejected_without_weakening_absolute_script_selectors() {
    for name in [
        "",
        ".main",
        "hermes..main",
        "hermes_cli.*",
        "hermes-cli.main",
        "-m hermes_cli.main",
        "C:\\hermes\\main.py",
        "hermes/main",
        " main",
        "main\n",
        "1module",
        "模块",
    ] {
        let value = serde_json::json!({"rules":[{"id":"module", "action":"intercept", "process_entry_points":[{"kind":"module", "runtime":"python", "name":name}]}]});
        assert!(
            serde_json::from_value::<TlsDecryptionPolicy>(value)
                .unwrap()
                .validate()
                .is_err(),
            "{name}"
        );
    }
    let invalid: TlsDecryptionPolicy = serde_json::from_value(serde_json::json!({
        "rules":[{"id":"script", "action":"intercept", "process_entry_points":[{"kind":"script", "path":"hermes_cli.main"}]}]
    }))
    .unwrap();
    assert!(invalid.validate().is_err());
    let policy = policy();
    let serialized = serde_json::to_value(&policy).unwrap();
    assert_eq!(
        serialized["rules"][0]["process_entry_points"][0]["name"],
        "hermes_cli.main"
    );
    assert!(serialized["rules"][1].get("process_entry_points").is_none());
    assert!(
        serde_json::from_value::<TlsDecryptionPolicy>(serialized)
            .unwrap()
            .validate()
            .is_ok()
    );
}

#[tokio::test]
async fn tls_certificates_follow_configured_module_rules_and_defaults() {
    // Each client trusts only the CA selected by policy. An unintended decrypt
    // or bypass fails TLS, including when the policy explicitly decrypts Python.
    let origin_ca = test_ca();
    let host = "api.openai.com";
    for (module, policy, intercepted) in [
        (None, policy(), false),
        (Some("other.main"), policy(), false),
        (Some("hermes_cli.main"), policy(), true),
        (
            None,
            serde_json::from_value(serde_json::json!({"default_action":"intercept"})).unwrap(),
            true,
        ),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let acceptor = TlsAcceptor::from(
            MitmTlsAuthority::from_ca(&origin_ca)
                .unwrap()
                .server_config_for_sni(host)
                .await
                .unwrap(),
        );
        let upstream = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            assert!(
                read_http_head(&mut stream)
                    .await
                    .starts_with("GET /opaque HTTP/1.1")
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                .await
                .unwrap();
            stream.shutdown().await.unwrap();
        });
        let (client, server) = connected_pair().await;
        let source = SourceProcess::new(Some(42), Some("python.exe".to_owned()), None)
            .with_entry_point(module.map(|value| {
                ProcessEntry::module(ModuleRuntime::Python, value.to_owned()).unwrap()
            }));
        let flow = AcceptedTcpFlow::from_boxed_parts(
            Box::new(server),
            None,
            None,
            OriginalDestination::from(address),
            Some(source),
        );
        let mitm_ca = test_ca();
        let mut mitm = test_mitm_engine_trusting(&mitm_ca)
            .with_tls_decryption_policy(policy)
            .unwrap();
        mitm.upstream_tls_config = test_client_config_trusting(&origin_ca);
        let worker = tokio::spawn(async move { mitm.handle_flow(flow).await });
        let mut client = TlsConnector::from(test_client_config_trusting(if intercepted {
            &mitm_ca
        } else {
            &origin_ca
        }))
        .connect(ServerName::try_from(host).unwrap().to_owned(), client)
        .await
        .unwrap();
        client
            .write_all(b"GET /opaque HTTP/1.1\r\nHost: api.openai.com\r\n\r\n")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK"));
        assert_eq!(
            matches!(
                worker.await.unwrap().unwrap(),
                TransparentFlowOutcome::Intercepted(_)
            ),
            intercepted
        );
        upstream.await.unwrap();
    }
}

#[test]
fn python_connections_obey_rule_order_and_all_configured_actions() {
    for (action, expected) in [
        ("intercept", TlsDecryptionAction::Intercept),
        ("redirect", TlsDecryptionAction::Redirect),
        ("block", TlsDecryptionAction::Block),
        ("passthrough", TlsDecryptionAction::Passthrough),
    ] {
        let mut rule = serde_json::json!({"id":"operator-first", "action":action, "destination_hosts":["api.openai.com"]});
        if expected == TlsDecryptionAction::Redirect {
            rule["target"] = serde_json::json!("other.test");
        }
        let mut policy = policy();
        policy
            .rules
            .insert(0, serde_json::from_value(rule).unwrap());
        policy.validate().unwrap();
        for module in [None, Some("hermes_cli.main"), Some("other.main")] {
            let source = SourceProcess::new(None, Some("python.exe".to_owned()), None)
                .with_entry_point(module.map(|name| {
                    ProcessEntry::module(ModuleRuntime::Python, name.to_owned()).unwrap()
                }));
            let decision = policy.decide(TlsDecryptionContext::new(
                Some("api.openai.com"),
                Some(&source),
            ));
            assert_eq!(decision.action(), expected);
            assert_eq!(decision.matched_rule_id(), Some("operator-first"));
        }
    }
}
