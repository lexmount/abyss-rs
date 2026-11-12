//! Semantic writes preserve provider documents and selected credential carriers.

use abyss_mitm::{RequestEditor, RequestTransport};
use abyss_plugin_protocol::inspection::ModifyAction;
use serde_json::json;

use super::*;
use crate::{HarnessUsageConfig, RequestActionError, RequestActions};

struct EditableRequest {
    flow: FlowContext,
    head: Request<()>,
    body: CapturedBody,
}

#[test]
fn provider_actions_replace_prefix_preserve_operation_and_refresh_context() {
    for (path, operation) in [
        ("/backend-api/codex/responses", "/responses"),
        ("/v1/responses/compact", "/responses/compact"),
        ("/v1/chat/completions", "/chat/completions"),
        (
            "/gateway/responses/v1/chat/completions",
            "/chat/completions",
        ),
        ("/v1/messages", "/messages"),
    ] {
        let source = EditableRequest::new(
            &format!("{path}?api-version=test"),
            &json!({"input":"hi", "messages":[], "model":"original"}),
        );
        let mut request = RequestEditor::new(source.view(RequestTransport::Http));
        let actions = RequestActions::new(&request.view());
        for base in [
            "https://first.test/v2/",
            "http://[::1]:8123/gateway/",
            "http://127.0.0.1:8123/gateway/",
        ] {
            actions
                .apply(
                    &mut request,
                    Box::new([ModifyAction::SetProvider(base.into())]),
                )
                .unwrap();
            assert_eq!(
                request.view().head.uri().to_string(),
                format!("{}{operation}?api-version=test", base.trim_end_matches('/'))
            );
            assert_eq!(request.view().body.bytes(), source.body.bytes());
        }
        actions
            .apply(
                &mut request,
                Box::new([
                    ModifyAction::SetAuthToken("new-provider-token".into()),
                    ModifyAction::SetModel("provider-model".into()),
                ]),
            )
            .unwrap();
        let context = AgentRequestParser::parse(
            &request.view(),
            &HarnessUsageConfig::default(),
            "routed".into(),
        );
        assert_eq!(
            context.provider.as_deref(),
            Some("http://127.0.0.1:8123/gateway")
        );
        assert!(context.provider_writable);
        assert_eq!(context.auth_token.as_deref(), Some("new-provider-token"));
        assert_eq!(
            context.agent.unwrap().model.as_deref(),
            Some("provider-model")
        );
        assert_eq!(request.view().head.headers()["host"], "127.0.0.1:8123");
        let result = request.finish(());
        assert_eq!(result.upstream.unwrap().host(), Some("127.0.0.1"));
    }
}

#[test]
fn provider_requires_an_http_origin_and_rejects_established_websocket_changes() {
    let source = EditableRequest::new("/v1/responses", &json!({"input":"hi"}));
    for base in [
        "relative/path",
        "ftp://provider.test",
        "https://user:pass@provider.test",
        "https://provider.test?q=1",
        "https://provider.test/#fragment",
        "https://provider.test:70000",
        "https://provider.test:0",
        "https://provider.test:invalid",
    ] {
        let mut request = RequestEditor::new(source.view(RequestTransport::Http));
        let error = RequestActions::new(&request.view()).apply(
            &mut request,
            Box::new([ModifyAction::SetProvider(base.into())]),
        );
        assert!(
            matches!(error, Err(RequestActionError::InvalidProvider)),
            "{base}"
        );
    }
    let mut request =
        RequestEditor::new(source.view(RequestTransport::WebSocketText { sequence: 1 }));
    assert!(matches!(
        RequestActions::new(&request.view()).apply(
            &mut request,
            Box::new([ModifyAction::SetProvider("https://provider.test".into())])
        ),
        Err(RequestActionError::ProviderUnavailable)
    ));
}

#[test]
fn websocket_upgrade_can_select_a_provider_without_a_body() {
    let mut source = EditableRequest::new("/backend-api/codex/responses", &json!({}));
    source.body = CapturedBody::from_bytes(Vec::new().into());
    let mut request = RequestEditor::new(source.view(RequestTransport::Http));
    let actions = RequestActions::new(&request.view());
    actions
        .apply(
            &mut request,
            Box::new([ModifyAction::SetProvider("https://provider.test/v1".into())]),
        )
        .unwrap();
    assert_eq!(
        request.view().head.uri(),
        "https://provider.test/v1/responses"
    );
}

impl EditableRequest {
    fn new(path: &str, document: &serde_json::Value) -> Self {
        Self {
            flow: FlowContext::from_optional_addrs(
                None,
                None,
                OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
                TransparentProtocol::PlainHttp,
                None,
            ),
            head: Request::builder()
                .uri(path)
                .header("host", "api.openai.com")
                .body(())
                .unwrap(),
            body: CapturedBody::from_bytes(serde_json::to_vec(document).unwrap().into()),
        }
    }

    fn view(&self, transport: RequestTransport) -> RequestView<'_> {
        RequestView {
            flow: &self.flow,
            head: &self.head,
            body: &self.body,
            transport,
        }
    }
}

#[test]
fn ordered_actions_preserve_unknown_fields_and_remove_null_models() {
    for path in ["/v1/responses", "/v1/chat/completions", "/v1/messages"] {
        let original =
            json!({"model":null,"messages":[],"input":"hi","unknown":{"keep":[1_u32,2_u32]}});
        let source = EditableRequest::new(path, &original);
        let mut request = RequestEditor::new(source.view(RequestTransport::Http));
        let actions = RequestActions::new(&request.view());
        actions
            .apply(
                &mut request,
                Box::new([
                    ModifyAction::SetModel("first".into()),
                    ModifyAction::RemoveModel,
                    ModifyAction::SetModel("last".into()),
                    ModifyAction::SetAuthToken("secret".into()),
                ]),
            )
            .unwrap();
        assert_eq!(request.view().body.json().unwrap()["model"], "last");
        assert_eq!(
            request.view().body.json().unwrap()["unknown"],
            original["unknown"]
        );
        assert_eq!(
            request.view().head.headers()["authorization"],
            "Bearer secret"
        );
        actions
            .apply(
                &mut request,
                Box::new([ModifyAction::RemoveModel, ModifyAction::RemoveAuthToken]),
            )
            .unwrap();
        assert!(request.view().body.json().unwrap().get("model").is_none());
        assert!(!request.view().head.headers().contains_key("authorization"));
    }
}

#[test]
fn authentication_binding_uses_carrier_or_known_host_without_guessing_from_protocol() {
    for (host, header, value, writable) in [
        ("api.openai.com", None, "", true),
        ("api.anthropic.com", None, "", true),
        ("gateway.invalid", None, "", false),
        (
            "gateway.invalid",
            Some("authorization"),
            "Bearer initial",
            true,
        ),
        ("gateway.invalid", Some("x-api-key"), "initial", true),
        (
            "gateway.invalid",
            Some("anthropic-api-key"),
            "initial",
            true,
        ),
        ("api.openai.com", Some("authorization"), "Basic abc", false),
    ] {
        let mut source = EditableRequest::new("/v1/responses", &json!({"input":"hi"}));
        source
            .head
            .headers_mut()
            .insert("host", host.parse().unwrap());
        if let Some(header) = header {
            source
                .head
                .headers_mut()
                .insert(header, value.parse().unwrap());
        }
        if let Some(header) = header {
            source
                .head
                .headers_mut()
                .append(header, value.parse().unwrap());
        }
        let mut request = RequestEditor::new(source.view(RequestTransport::Http));
        let actions = RequestActions::new(&request.view());
        let result = actions.apply(
            &mut request,
            Box::new([ModifyAction::SetAuthToken("allocated".into())]),
        );
        assert_eq!(result.is_ok(), writable, "{host} {header:?}");
        if writable {
            let selected = header.unwrap_or(if host == "api.anthropic.com" {
                "x-api-key"
            } else {
                "authorization"
            });
            assert_eq!(
                request.view().head.headers()[selected],
                if selected == "authorization" {
                    "Bearer allocated"
                } else {
                    "allocated"
                }
            );
            assert_eq!(
                request
                    .view()
                    .head
                    .headers()
                    .get_all(selected)
                    .iter()
                    .count(),
                1
            );
            // Removing the credential does not lose its selected binding within a chain.
            actions
                .apply(&mut request, Box::new([ModifyAction::RemoveAuthToken]))
                .unwrap();
            actions
                .apply(
                    &mut request,
                    Box::new([ModifyAction::SetAuthToken("again".into())]),
                )
                .unwrap();
            assert!(
                request.finish(()).body.is_none(),
                "auth-only edits retain original bytes"
            );
        }
    }
}

#[test]
fn websocket_edits_preserve_envelope_and_cannot_change_connection_token() {
    let source = EditableRequest::new(
        "/v1/responses",
        &json!({"type":"response.create","event_id":"keep","response":{"model":"old","input":[],"custom":42_u32}}),
    );
    let mut request =
        RequestEditor::new(source.view(RequestTransport::WebSocketText { sequence: 1 }));
    let actions = RequestActions::new(&request.view());
    actions
        .apply(
            &mut request,
            Box::new([ModifyAction::SetModel("new".into())]),
        )
        .unwrap();
    let document = request.view().body.json().unwrap();
    assert_eq!(document["event_id"], "keep");
    assert_eq!(document["response"]["model"], "new");
    assert_eq!(document["response"]["custom"], 42_u32);
    assert!(matches!(
        actions.apply(
            &mut request,
            Box::new([ModifyAction::SetAuthToken("private".into())])
        ),
        Err(RequestActionError::AuthenticationUnavailable)
    ));
}

#[test]
fn invalid_tokens_have_value_free_errors() {
    let source = EditableRequest::new("/v1/responses", &json!({"model":null,"input":[]}));
    let mut request = RequestEditor::new(source.view(RequestTransport::Http));
    let actions = RequestActions::new(&request.view());
    let error = actions
        .apply(
            &mut request,
            Box::new([ModifyAction::SetAuthToken("private\r\ninjected".into())]),
        )
        .unwrap_err();
    assert!(!error.to_string().contains("private"));
}

#[test]
fn unsupported_requests_remain_inspectable() {
    let mut source = EditableRequest::new("/unknown", &json!({"model":null}));
    source
        .head
        .headers_mut()
        .insert("authorization", "Bearer readable-secret".parse().unwrap());
    let view = source.view(RequestTransport::Http);
    let context = AgentRequestParser::parse(
        &view,
        &crate::HarnessUsageConfig::default(),
        "request".to_owned(),
    );
    assert_eq!(context.auth_token.as_deref(), Some("readable-secret"));
    assert!(!format!("{context:?}").contains("readable-secret"));
    assert!(!context.model_writable);
    assert!(context.auth_token_writable);
    let actions = RequestActions::new(&view);
    let mut editor = RequestEditor::new(view);
    assert!(matches!(
        actions.apply(&mut editor, Box::new([ModifyAction::RemoveModel])),
        Err(RequestActionError::ModelUnavailable)
    ));
    let source = EditableRequest::new("/v1/responses", &json!({"model":null}));
    let mut editor = RequestEditor::new(source.view(RequestTransport::Http));
    RequestActions::new(&editor.view())
        .apply(&mut editor, Box::new([ModifyAction::RemoveModel]))
        .unwrap();
    assert!(editor.view().body.json().unwrap().get("model").is_none());
}
