//! Count stage invocations while delegating all parsing and assembly to real implementations.

use std::{cell::RefCell, marker::PhantomData};

use abyss_mitm::{
    FlowContext, OriginalDestination, RequestTransport, RequestView, TransparentProtocol,
};
use http::{Request, Response};
use serde_json::json;

use super::*;
use crate::{
    AgentRequestParser,
    protocol::openai::{responses::ResponsesParser, shared::http::OpenAiHttpExchange},
};

thread_local! {
    static STAGES: RefCell<Vec<&'static str>> = const { RefCell::new(Vec::new()) };
}

struct Recording<P>(PhantomData<P>);

impl<P: ProtocolParser> ProtocolParser for Recording<P> {
    const PROTOCOL: LlmProtocol = P::PROTOCOL;
    fn parse_request(payload: Option<&Value>, truncated: bool) -> RequestContent {
        STAGES.with_borrow_mut(|stages| stages.push("parse_request"));
        P::parse_request(payload, truncated)
    }
    fn parse_response(values: &[Value], incomplete: bool) -> ResponseContent {
        STAGES.with_borrow_mut(|stages| stages.push("parse_response"));
        P::parse_response(values, incomplete)
    }
}

#[test]
fn both_http_modes_call_one_response_parser_and_one_shared_assembler() {
    for inspected in [false, true] {
        let flow = FlowContext::from_optional_addrs(
            None,
            None,
            OriginalDestination::from("127.0.0.1:443".parse::<std::net::SocketAddr>().unwrap()),
            TransparentProtocol::PlainHttp,
            None,
        );
        let head = Request::builder()
            .uri("/v1/responses")
            .header("host", "api.openai.com")
            .body(())
            .unwrap();
        let mut body =
            CapturedBody::from_bytes(br#"{"model":"requested","input":"hello"}"#.to_vec().into());
        if inspected {
            let parsed = AgentRequestParser::prepare(&RequestView {
                flow: &flow,
                head: &head,
                body: &body,
                transport: RequestTransport::Http,
            });
            body.extensions_mut().insert(parsed);
        }
        let response = json!({"model":"actual","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"answer"}]}]});
        let exchange = HttpExchange::new(
            flow,
            head.map(|()| body),
            Response::new(CapturedBody::from_bytes(
                response.to_string().into_bytes().into(),
            )),
        );
        STAGES.with_borrow_mut(Vec::clear);
        let parsed = parse_http_exchange::<Recording<ResponsesParser>, _, _>(
            &exchange,
            |exchange, request, response| {
                STAGES.with_borrow_mut(|stages| stages.push("assemble_exchange"));
                OpenAiHttpExchange::assemble_exchange(exchange, request, response)
            },
        )
        .unwrap();
        assert_eq!(parsed.request_conversation.entries[0].text, "hello");
        assert_eq!(parsed.response_conversation.entries[0].text, "answer");
        assert_eq!(parsed.model.as_deref(), Some("actual"));
        STAGES.with_borrow(|stages| {
            assert_eq!(
                stages.as_slice(),
                if inspected {
                    &["parse_response", "assemble_exchange"][..]
                } else {
                    &["parse_request", "parse_response", "assemble_exchange"][..]
                }
            );
        });
    }
}
