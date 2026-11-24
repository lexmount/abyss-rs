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
            .with_application_id(Some("com.anthropic.claudefordesktop.helper".to_owned())),
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
async fn desktop_bundled_claude_code_uses_first_matching_harness() {
    for app in ["Claude", "Claude-3p"] {
        for application_id in [None, Some("com.anthropic.claude-code")] {
            let scenario = Scenario::new(json!({}));
            scenario
                .http_from_source(
                    &[
                        ("user-agent", "claude-code/2.1.321"),
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
                // The existing Desktop path matcher precedes the Code detector.
                assert_eq!(event.agent.name, "claude-desktop");
                assert_eq!(event.session_id, "code-session");
                assert!(event.turn_id.is_none());
            }
        }
    }
}

#[tokio::test]
async fn claude_first_enabled_match_follows_existing_policy_filtering() {
    let mut sources = desktop_sources()
        .into_iter()
        .map(|source| ("claude-desktop", source))
        .collect::<Vec<_>>();
    sources.push((
        "claude-desktop",
        bundled_code_source("Claude", Some("com.anthropic.claude-code")),
    ));
    sources.push((
        "claude-code",
        SourceProcess::new(None, Some("claude".to_owned()), None),
    ));
    for (first_match, source) in sources {
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
                let expected = if first_match == "claude-desktop" && desktop_enabled {
                    Some("claude-desktop")
                } else if code_enabled {
                    Some("claude-code")
                } else {
                    None
                };
                let events = scenario.sink.0.lock();
                assert_eq!(
                    events.len(),
                    if expected.is_some() { 2 } else { 0 },
                    "{source:?}"
                );
                assert!(
                    events
                        .iter()
                        .all(|event| Some(event.agent.name.as_str()) == expected)
                );
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
