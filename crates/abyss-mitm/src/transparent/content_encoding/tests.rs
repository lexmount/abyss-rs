//! Content coding contracts, corruption handling, and independent capture budgets.

mod logging;

use std::io::Write;

use super::*;

const PAYLOAD: &[u8] = br#"{"model":"test","messages":[{"role":"user","content":"hello"}]}"#;

fn encode(coding: &str, bytes: &[u8]) -> Vec<u8> {
    match coding {
        "gzip" => {
            let mut writer =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(bytes).unwrap();
            writer.finish().unwrap()
        }
        "deflate" => {
            let mut writer =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            writer.write_all(bytes).unwrap();
            writer.finish().unwrap()
        }
        "br" => {
            let mut writer = ::brotli::CompressorWriter::new(Vec::new(), 4096, 5, 22);
            writer.write_all(bytes).unwrap();
            writer.into_inner()
        }
        "zstd" => zstd::stream::encode_all(bytes, 1).unwrap(),
        _ => bytes.to_vec(),
    }
}

fn decode(coding: &str, raw: Vec<u8>, truncated: bool, limit: usize) -> CapturedBody {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, coding.parse().unwrap());
    let mut body = if truncated {
        CapturedBody::from_truncated_bytes(raw.into())
    } else {
        CapturedBody::from_bytes(raw.into())
    }
    .with_decode_limit(limit);
    body.mark_pending(&headers);
    assert!(body.bytes().is_empty());
    ContentDecoder::decode_body(&headers, &mut body, false);
    body
}

#[test]
fn all_codings_preserve_raw_bytes_and_provide_json() {
    for coding in ["gzip", "deflate", "br", "zstd", "identity"] {
        let encoded = encode(coding, PAYLOAD);
        let body = decode(coding, encoded.clone(), false, 4096);
        assert_eq!(
            body.decoding_status(),
            BodyDecodingStatus::Complete,
            "{coding}"
        );
        assert_eq!(body.bytes(), PAYLOAD, "{coding}");
        assert_eq!(body.raw_bytes(), encoded);
        assert_eq!(body.json().unwrap()["model"], "test");
        assert!(!body.truncated());
    }
}

#[test]
fn repeated_and_stacked_codings_are_decoded_in_reverse_order() {
    let mut headers = HeaderMap::new();
    headers.append(CONTENT_ENCODING, " GZip, identity ".parse().unwrap());
    headers.append(CONTENT_ENCODING, " br, zstd ".parse().unwrap());
    let encoded = encode("zstd", &encode("br", &encode("gzip", PAYLOAD)));
    let mut body = CapturedBody::from_bytes(encoded.into());
    ContentDecoder::decode_body(&headers, &mut body, false);
    assert_eq!(body.bytes(), PAYLOAD);
    assert_eq!(body.decoding_status(), BodyDecodingStatus::Complete);
}

#[test]
fn corrupt_incomplete_and_trailing_data_do_not_become_plaintext() {
    for coding in ["gzip", "deflate", "br", "zstd"] {
        let encoded = encode(coding, PAYLOAD);
        let mut trailing = encoded.clone();
        trailing.extend_from_slice(b"garbage");
        for invalid in [
            b"not compressed".to_vec(),
            encoded[..encoded.len() - 1].to_vec(),
            trailing,
        ] {
            let body = decode(coding, invalid.clone(), false, 4096);
            assert_eq!(
                body.decoding_status(),
                BodyDecodingStatus::InvalidData,
                "{coding}"
            );
            assert!(body.bytes().is_empty());
            assert!(body.json().is_none());
            assert_eq!(body.raw_bytes(), invalid);
            assert!(body.truncated());
        }
    }
}

#[test]
fn capture_truncation_and_output_expansion_keep_only_a_bounded_prefix() {
    let payload = b"long observed text ".repeat(4096);
    for coding in ["gzip", "deflate", "br", "zstd"] {
        let encoded = encode(coding, &payload);
        let body = decode(coding, encoded.clone(), false, 1024);
        assert_eq!(
            body.decoding_status(),
            BodyDecodingStatus::Truncated,
            "{coding}"
        );
        assert_eq!(body.bytes(), &payload[..1024], "{coding}");
        assert!(!body.raw_truncated());
        let body = decode(
            coding,
            encoded[..encoded.len() - 1].to_vec(),
            true,
            payload.len(),
        );
        assert_eq!(
            body.decoding_status(),
            BodyDecodingStatus::Truncated,
            "{coding}"
        );
        assert!(payload.starts_with(body.bytes()));
        assert!(body.raw_truncated());
    }
}

#[test]
fn exact_output_limit_and_empty_representations_are_complete() {
    for coding in ["gzip", "deflate", "br", "zstd"] {
        let payload = b"x".repeat(2048);
        let body = decode(coding, encode(coding, &payload), false, payload.len());
        assert_eq!(
            body.decoding_status(),
            BodyDecodingStatus::Complete,
            "{coding}"
        );
        let body = decode(coding, encode(coding, b""), false, 4096);
        assert_eq!(
            body.decoding_status(),
            BodyDecodingStatus::Complete,
            "{coding}"
        );
        assert!(body.bytes().is_empty());
    }
}

#[test]
fn concatenated_gzip_and_zstd_frames_are_supported() {
    for coding in ["gzip", "zstd"] {
        let encoded = [encode(coding, b"first"), encode(coding, b"second")].concat();
        assert_eq!(decode(coding, encoded, false, 4096).bytes(), b"firstsecond");
    }
}

#[test]
fn invalid_headers_and_excessive_chains_are_explicit() {
    for (coding, expected) in [
        ("future", BodyDecodingStatus::UnsupportedEncoding),
        ("gzip,", BodyDecodingStatus::InvalidEncoding),
        ("", BodyDecodingStatus::InvalidEncoding),
        (
            "identity,identity,identity,identity,identity",
            BodyDecodingStatus::BudgetExceeded,
        ),
    ] {
        assert_eq!(
            decode(coding, PAYLOAD.to_vec(), false, 4096).decoding_status(),
            expected
        );
    }
    let mut headers = HeaderMap::new();
    headers.insert(TRANSFER_ENCODING, "gzip, chunked".parse().unwrap());
    let mut body = CapturedBody::from_bytes(Bytes::from_static(PAYLOAD));
    ContentDecoder::decode_body(&headers, &mut body, false);
    assert_eq!(
        body.decoding_status(),
        BodyDecodingStatus::UnsupportedTransferEncoding
    );
    assert!(body.bytes().is_empty());
}

#[test]
fn expired_budget_fails_without_unbounded_work() {
    let decoder = ContentDecoder {
        deadline: Instant::now(),
        limit: 4096,
    };
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
    assert_eq!(
        decoder.decode(&headers, encode("gzip", PAYLOAD).into(), false),
        Err(BodyDecodingStatus::BudgetExceeded)
    );
}

#[test]
fn bodyless_response_metadata_does_not_require_a_compressed_stream() {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_ENCODING, "gzip".parse().unwrap());
    let mut body = CapturedBody::from_bytes(Bytes::new());
    ContentDecoder::decode_body(&headers, &mut body, true);
    assert_eq!(body.decoding_status(), BodyDecodingStatus::Complete);
}
