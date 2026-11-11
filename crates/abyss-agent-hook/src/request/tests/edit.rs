//! Semantic writes preserve provider documents and selected credential carriers.

use abyss_mitm::{RequestEditor, RequestTransport};
use abyss_plugin_protocol::inspection::ModifyAction;
use serde_json::json;

use super::*;
use crate::{RequestActionError, RequestActions};

struct EditableRequest {
    flow: FlowContext,
    head: Request<()>,
    body: CapturedBody,
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
                request.finish(http::Extensions::new()).body.is_none(),
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
fn unsupported_and_signed_requests_remain_inspectable() {
    for (path, signed) in [("/unknown", false), ("/v1/responses", true)] {
        let mut source = EditableRequest::new(path, &json!({"model":null}));
        source
            .head
            .headers_mut()
            .insert("authorization", "Bearer readable-secret".parse().unwrap());
        if signed {
            source
                .head
                .headers_mut()
                .insert("signature-input", "sig=()".parse().unwrap());
        }
        let view = source.view(RequestTransport::Http);
        let context = AgentRequestParser::parse(
            &view,
            &crate::HarnessUsageConfig::default(),
            "request".to_owned(),
        );
        assert_eq!(context.auth_token.as_deref(), Some("readable-secret"));
        assert!(!format!("{context:?}").contains("readable-secret"));
        assert!(!context.model_writable);
        assert_eq!(context.auth_token_writable, !signed);
        let actions = RequestActions::new(&view);
        let mut editor = RequestEditor::new(view);
        assert!(matches!(
            actions.apply(&mut editor, Box::new([ModifyAction::RemoveModel])),
            Err(RequestActionError::ModelUnavailable)
        ));
    }
    let source = EditableRequest::new("/v1/responses", &json!({"model":null}));
    let mut editor = RequestEditor::new(source.view(RequestTransport::Http));
    RequestActions::new(&editor.view())
        .apply(&mut editor, Box::new([ModifyAction::RemoveModel]))
        .unwrap();
    assert!(editor.view().body.json().unwrap().get("model").is_none());
}
