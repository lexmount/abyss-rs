//! Ready captures bypass decoding without losing validation or capture limits.

use std::{net::SocketAddr, sync::Arc};

use super::super::*;
use super::PAYLOAD;
use crate::{FlowContext, OriginalDestination, TransparentProtocol};

#[test]
fn identity_captures_reuse_the_existing_json_view() {
    for coding in [None, Some("identity"), Some("IDENTITY, identity")] {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, "chunked".parse().unwrap());
        if let Some(coding) = coding {
            headers.append(CONTENT_ENCODING, coding.parse().unwrap());
            headers.append(CONTENT_ENCODING, "identity".parse().unwrap());
        }
        let mut body = CapturedBody::from_bytes(Bytes::from_static(PAYLOAD));
        let model_allocation = body.json().unwrap()["model"].as_str().unwrap().as_ptr();
        ContentDecoder::prepare_body(&headers, &mut body);
        assert!(ContentDecoder::body_ready(&headers, &body, false));
        // A compressed peer body can still send this body through decode_exchange.
        ContentDecoder::decode_body(&headers, &mut body, false);
        assert_eq!(body.bytes(), PAYLOAD);
        assert_eq!(body.decoding_status(), BodyDecodingStatus::Complete);
        assert_eq!(
            body.json().unwrap()["model"].as_str().unwrap().as_ptr(),
            model_allocation,
            "identity captures must not allocate and parse their JSON again"
        );
    }
}

#[test]
fn inspected_compressed_capture_reuses_decoded_bytes_and_json_for_observation() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
    let mut body = super::decode("gzip", super::encode("gzip", PAYLOAD), false, 4096);
    let prepared = Arc::new("parsed request".to_owned());
    body.extensions_mut().insert(prepared.clone());
    let decoded_allocation = body.bytes().as_ptr();
    let model_allocation = body.json().unwrap()["model"].as_str().unwrap().as_ptr();
    ContentDecoder::prepare_body(&headers, &mut body);
    assert!(ContentDecoder::body_ready(&headers, &body, false));
    ContentDecoder::decode_body(&headers, &mut body, false);
    assert_eq!(body.bytes().as_ptr(), decoded_allocation);
    assert_eq!(
        body.json().unwrap()["model"].as_str().unwrap().as_ptr(),
        model_allocation
    );
    assert_eq!(body.bytes(), PAYLOAD);
    assert!(Arc::ptr_eq(
        body.extensions().get::<Arc<String>>().unwrap(),
        &prepared
    ));
    // A smaller observation budget must still be respected on an already decoded capture.
    body = body.with_decode_limit(8);
    ContentDecoder::decode_body(&headers, &mut body, false);
    assert!(body.truncated());
    assert!(body.bytes().len() <= 8);
    assert!(body.extensions().get::<Arc<String>>().is_none());
}

#[test]
fn either_compressed_side_requires_processing() {
    let plain = exchange();
    assert!(!ContentDecoder::requires_processing(&plain));
    for coding in ["gzip", "deflate", "br", "zstd", "identity, gzip"] {
        let mut request = plain.clone();
        request
            .request
            .headers_mut()
            .insert(CONTENT_ENCODING, coding.parse().unwrap());
        assert!(
            ContentDecoder::requires_processing(&request),
            "request {coding}"
        );
        let mut response = plain.clone();
        response
            .response
            .headers_mut()
            .insert(CONTENT_ENCODING, coding.parse().unwrap());
        assert!(
            ContentDecoder::requires_processing(&response),
            "response {coding}"
        );
    }
}

#[test]
fn invalid_metadata_cannot_use_the_identity_fast_path() {
    for (name, value, expected) in [
        (
            CONTENT_ENCODING,
            "future",
            BodyDecodingStatus::UnsupportedEncoding,
        ),
        (
            CONTENT_ENCODING,
            "identity,",
            BodyDecodingStatus::InvalidEncoding,
        ),
        (
            CONTENT_ENCODING,
            "identity,identity,identity,identity,identity",
            BodyDecodingStatus::BudgetExceeded,
        ),
        (
            TRANSFER_ENCODING,
            "gzip, chunked",
            BodyDecodingStatus::UnsupportedTransferEncoding,
        ),
    ] {
        let mut exchange = exchange();
        exchange
            .response
            .headers_mut()
            .insert(name, value.parse().unwrap());
        assert!(ContentDecoder::requires_processing(&exchange), "{value}");
        let decoded = ContentDecoder::decode_exchange(exchange);
        assert_eq!(
            decoded.response.body().decoding_status(),
            expected,
            "{value}"
        );
        assert!(decoded.response.body().bytes().is_empty(), "{value}");
    }
}

#[test]
fn identity_fast_path_preserves_truncation_and_enforces_smaller_limits() {
    let mut exchange = exchange();
    *exchange.request.body_mut() =
        CapturedBody::from_truncated_bytes(Bytes::from_static(b"prefix")).with_decode_limit(6);
    assert!(!ContentDecoder::requires_processing(&exchange));
    assert!(exchange.request.body().truncated());
    *exchange.response.body_mut() =
        CapturedBody::from_bytes(Bytes::from_static(b"longer")).with_decode_limit(3);
    assert!(ContentDecoder::requires_processing(&exchange));
    let decoded = ContentDecoder::decode_exchange(exchange);
    assert_eq!(decoded.request.body().bytes(), b"prefix");
    assert_eq!(decoded.response.body().bytes(), b"lon");
    assert_eq!(
        decoded.response.body().decoding_status(),
        BodyDecodingStatus::Truncated
    );
}

#[test]
fn custom_capture_limit_cannot_bypass_the_observation_hard_cap() {
    let mut exchange = exchange();
    *exchange.response.body_mut() =
        CapturedBody::from_bytes(vec![b'x'; DEFAULT_MAX_HTTP1_BODY_BYTES.saturating_add(1)].into())
            .with_decode_limit(usize::MAX);
    assert!(ContentDecoder::requires_processing(&exchange));
    let decoded = ContentDecoder::decode_exchange(exchange);
    assert_eq!(
        decoded.response.body().bytes().len(),
        DEFAULT_MAX_HTTP1_BODY_BYTES
    );
    assert_eq!(
        decoded.response.body().decoding_status(),
        BodyDecodingStatus::Truncated
    );
}

fn exchange() -> HttpExchange {
    let address = SocketAddr::from(([127, 0, 0, 1], 443));
    HttpExchange {
        flow: FlowContext::new(
            address,
            address,
            OriginalDestination::from(address),
            TransparentProtocol::PlainHttp,
        ),
        request: http::Request::new(CapturedBody::from_bytes(Bytes::from_static(PAYLOAD))),
        response: http::Response::new(CapturedBody::from_bytes(Bytes::from_static(PAYLOAD))),
        request_sent_at: std::time::SystemTime::UNIX_EPOCH,
        response_ended_at: std::time::SystemTime::UNIX_EPOCH,
    }
}
