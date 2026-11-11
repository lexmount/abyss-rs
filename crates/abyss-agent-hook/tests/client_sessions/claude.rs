//! Claude Desktop/Cowork and bundled Code attribution through event delivery.
//! Process shapes come from diagnostics; headers and model payloads are synthetic.

use super::{ContentCategory, Scenario, SourceProcess, json};

fn desktop_sources() -> Vec<SourceProcess> {
    vec![
        SourceProcess::new(
            None,
            Some("Claude".to_owned()),
            Some("/Applications/Claude.app/Contents/MacOS/Claude".to_owned()),
        )
        .with_application_id(Some("com.anthropic.claudefordesktop".to_owned())),
        SourceProcess::new(
            None,
            Some("Claude Helper".to_owned()),
            Some(
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper"
                    .to_owned(),
            ),
        )
        .with_application_id(Some("com.anthropic.claudefordesktop.helper".to_owned())),
        SourceProcess::new(None, None, None)
            .with_application_id(Some("com.anthropic.claudefordesktop".to_owned())),
        // A known Desktop application identity outranks a misleading parent directory.
        SourceProcess::new(
            None,
            Some("Claude".to_owned()),
            Some("/Users/test/claude-code/Claude.app/Contents/MacOS/Claude".to_owned()),
        )
        .with_application_id(Some("com.anthropic.claudefordesktop".to_owned())),
    ]
}

fn bundled_code_source(app: &str, application_id: Option<&str>) -> SourceProcess {
    SourceProcess::new(
        None,
        Some("claude".to_owned()),
        Some(format!(
            "/Users/test/Library/Application Support/{app}/claude-code/2.1.321/build/claude.app/Contents/MacOS/claude"
        )),
    )
    .with_application_id(application_id.map(str::to_owned))
}

#[tokio::test]
async fn cowork_desktop_sources_emit_events_despite_code_fingerprints() {
    for source in desktop_sources() {
        for user_agent in ["claude/1.0.0", "claude-code/2.1.321"] {
            let scenario = Scenario::new(json!({}));
            scenario
                .http_from_source(
                    &[
                        ("user-agent", user_agent),
                        ("x-claude-code-prompt-id", "code-compatibility-turn"),
                    ],
                    "/v1/messages",
                    "cowork-reply",
                    Some(source.clone()),
                )
                .await;
            let events = scenario.sink.0.lock();
            assert_eq!(events.len(), 2, "{source:?} {user_agent}");
            for event in events.iter() {
                assert_eq!(event.agent.name, "claude-desktop");
                assert!(event.turn_id.is_none());
            }
            assert_eq!(events[0].token_usage.input_tokens, 3);
            assert_eq!(events[1].token_usage.output_tokens, 2);
        }
    }
}

#[tokio::test]
async fn cowork_desktop_headers_identify_proxy_requests_without_process_metadata() {
    for marker in [
        ("anthropic-client-platform", "desktop_app"),
        ("anthropic-client-app", "com.anthropic.claudefordesktop"),
    ] {
        let scenario = Scenario::new(json!({}));
        scenario
            .http(
                &[marker, ("user-agent", "claude-code/2.1.321")],
                "/v1/messages",
                "cowork-reply",
            )
            .await;
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), 2, "{marker:?}");
        assert!(
            events
                .iter()
                .all(|event| event.agent.name == "claude-desktop")
        );
        drop(events);
    }
}

#[tokio::test]
async fn desktop_bundled_claude_code_preserves_its_identity_and_declarations() {
    for app in ["Claude", "Claude-3p"] {
        for application_id in [None, Some("com.anthropic.claude-code")] {
            let scenario = Scenario::new(json!({}));
            scenario
                .http_from_source(
                    &[
                        ("user-agent", "claude-code/2.1.321"),
                        ("anthropic-client-platform", "desktop_app"),
                        ("x-claude-code-session-id", "code-session"),
                        ("x-claude-code-prompt-id", "code-turn"),
                    ],
                    "/v1/messages",
                    "code-reply",
                    Some(bundled_code_source(app, application_id)),
                )
                .await;
            let events = scenario.sink.0.lock();
            assert_eq!(events.len(), 2, "{app} {application_id:?}");
            for event in events.iter() {
                assert_eq!(event.agent.name, "claude-code");
                assert_eq!(event.agent.version.as_deref(), Some("2.1.321"));
                assert_eq!(event.session_id, "code-session");
                assert_eq!(event.turn_id.as_deref(), Some("code-turn"));
            }
        }
    }
}

#[tokio::test]
async fn claude_code_application_identity_is_sufficient_without_names_or_headers() {
    let scenario = Scenario::new(json!({}));
    scenario
        .http_from_source(
            &[],
            "/v1/messages",
            "code-reply",
            Some(
                SourceProcess::new(None, None, None)
                    .with_application_id(Some("com.anthropic.claude-code".to_owned())),
            ),
        )
        .await;
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|event| event.agent.name == "claude-code"));
    drop(events);
}

#[tokio::test]
async fn claude_identity_is_resolved_before_enablement_policy() {
    let mut sources = desktop_sources()
        .into_iter()
        .map(|source| ("claude-desktop", source))
        .collect::<Vec<_>>();
    sources.push((
        "claude-code",
        bundled_code_source("Claude", Some("com.anthropic.claude-code")),
    ));
    for (expected, source) in sources {
        for desktop_enabled in [true, false] {
            for code_enabled in [true, false] {
                let scenario = Scenario::new(json!({"harness_usage": {"config": {
                    "harnesses": {
                        "claude-desktop": {"enabled": desktop_enabled},
                        "claude-code": {"enabled": code_enabled}
                    }
                }}}));
                scenario
                    .http_from_source(
                        &[("user-agent", "claude/1.0.0")],
                        "/v1/messages",
                        "reply",
                        Some(source.clone()),
                    )
                    .await;
                let enabled = if expected == "claude-desktop" {
                    desktop_enabled
                } else {
                    code_enabled
                };
                let events = scenario.sink.0.lock();
                assert_eq!(events.len(), if enabled { 2 } else { 0 }, "{expected}");
                assert!(events.iter().all(|event| event.agent.name == expected));
                drop(events);
            }
        }
    }
}

#[tokio::test]
async fn cowork_uses_desktop_content_policy_instead_of_code_policy() {
    let scenario = Scenario::new(json!({"harness_usage": {"config": {
        "harnesses": {
            "claude-desktop": {"content": {"conversation_text": false}},
            "claude-code": {"content": {"conversation_text": true}}
        }
    }}}));
    scenario
        .http(
            &[
                ("anthropic-client-platform", "desktop_app"),
                ("user-agent", "claude-code/2.1.321"),
            ],
            "/v1/messages",
            "cowork-reply",
        )
        .await;
    let events = scenario.sink.0.lock();
    assert_eq!(events.len(), 2);
    for event in events.iter() {
        assert_eq!(event.agent.name, "claude-desktop");
        assert!(event.omitted.contains(&ContentCategory::ConversationText));
        assert!(
            event
                .conversation
                .as_ref()
                .unwrap()
                .entries
                .iter()
                .all(|entry| entry.text.is_empty())
        );
    }
}

#[tokio::test]
async fn standalone_claude_code_keeps_legacy_detection_without_desktop_identity() {
    for source in [
        None,
        Some(SourceProcess::new(
            None,
            Some("claude".to_owned()),
            Some("/Users/test/.local/share/claude/versions/2.1.314".to_owned()),
        )),
    ] {
        let scenario = Scenario::new(json!({}));
        scenario
            .http_from_source(
                &[("user-agent", "claude/2.1.314")],
                "/v1/messages",
                "code-reply",
                source,
            )
            .await;
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "claude-code"));
        drop(events);
    }
}

#[tokio::test]
async fn overlapping_desktop_requests_use_the_first_builtin_match() {
    for source in desktop_sources() {
        let scenario = Scenario::new(json!({}));
        scenario
            .http_from_source(
                &[
                    ("user-agent", "claude/1.0.0"),
                    ("x-codex-turn-metadata", "{}"),
                ],
                "/v1/messages",
                "reply",
                Some(source),
            )
            .await;
        let events = scenario.sink.0.lock();
        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| event.agent.name == "codex"));
        drop(events);
    }
}
