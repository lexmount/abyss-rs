//! Decoding diagnostics must never format the surrounding credential headers.

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use http::HeaderMap;

use super::super::{CapturedBody, ContentDecoder};

struct LogWriter(Arc<Mutex<Vec<u8>>>);

impl Write for LogWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("test log writer poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn decoding_logs_encoding_and_status_without_credentials() {
    let output = Arc::new(Mutex::new(Vec::new()));
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_ansi(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || LogWriter(writer.clone()))
        .finish();
    let mut headers = HeaderMap::new();
    headers.insert("content-encoding", "identity".parse().unwrap());
    headers.insert(
        "authorization",
        "Bearer secret-bearer-sentinel".parse().unwrap(),
    );
    headers.insert("x-api-key", "secret-key-sentinel".parse().unwrap());
    headers.insert("cookie", "secret-cookie-sentinel".parse().unwrap());
    let mut body = CapturedBody::from_bytes(Bytes::from_static(b"hello"));
    tracing::subscriber::with_default(subscriber, || {
        ContentDecoder::decode_body(&headers, &mut body, false);
    });
    let text = String::from_utf8(output.lock().unwrap().clone()).unwrap();
    assert!(text.contains("identity"), "diagnostics include the coding");
    assert!(text.contains("Complete"), "diagnostics include the result");
    assert!(
        !text.contains("sentinel"),
        "credential values must never enter decoding logs"
    );
    assert!(
        !text.contains("authorization"),
        "do not format the whole header map"
    );
}
