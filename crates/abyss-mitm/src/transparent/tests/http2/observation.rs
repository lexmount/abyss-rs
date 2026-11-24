//! Records HTTP/2 hook callbacks and serves the gated gzip test response.

use bytes::Bytes;
use flate2::{Compression, write::GzEncoder};
use http::{Request, Response, Version, header};
use parking_lot::Mutex;
use std::{
    future,
    io::Write as _,
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    sync::{Notify, mpsc},
    time::{sleep, timeout},
};

use super::{Fixture, Routing, read_body};
use crate::transparent::{
    FlowContext, HookFuture, HttpExchange, HttpResponseObserver, MitmHook, UncontrolledForwarding,
};

pub(super) const GZIP_PATH: &str = "/gzip-events";
const GZIP_RECORD: &[u8] = b"data: flushed\n\n";

#[derive(Clone, Default)]
pub(super) struct Capture {
    pub(super) exchanges: Arc<Mutex<Vec<HttpExchange>>>,
    probe: Option<Probe>,
}

impl MitmHook for Capture {
    fn on_http_exchange<'a>(&'a self, exchange: &'a HttpExchange) -> HookFuture<'a> {
        self.exchanges.lock().push(exchange.clone());
        Box::pin(future::ready(Ok(())))
    }

    fn observe_http_response(
        &self,
        _flow: &FlowContext,
        request: &Request<()>,
        response: &Response<()>,
    ) -> Option<Box<dyn HttpResponseObserver>> {
        let probe = self.probe.as_ref()?;
        (request.uri().path() == GZIP_PATH
            && response.headers().get(header::CONTENT_ENCODING)? == "gzip")
            .then(|| -> Box<dyn HttpResponseObserver> { Box::new(probe.clone()) })
    }
}

#[derive(Clone)]
struct Probe {
    decoded: mpsc::UnboundedSender<(SystemTime, Bytes)>,
    resume: Option<Arc<Notify>>,
}

impl HttpResponseObserver for Probe {
    fn on_http_response_chunk<'a>(&'a mut self, at: SystemTime, chunk: &'a [u8]) -> HookFuture<'a> {
        self.decoded
            .send((at, Bytes::copy_from_slice(chunk)))
            .unwrap();
        let resume = self.resume.take();
        Box::pin(async move {
            if let Some(resume) = resume {
                resume.notified().await;
            }
            Ok(())
        })
    }
}

pub(super) async fn serve_gzip(mut respond: h2::server::SendResponse<Bytes>, finish: &Notify) {
    let response = Response::builder()
        .version(Version::HTTP_2)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_ENCODING, "gzip")
        .body(())
        .unwrap();
    let mut stream = respond.send_response(response, false).unwrap();
    let mut gzip = GzEncoder::new(Vec::new(), Compression::fast());
    let parts: [&[u8]; 2] = GZIP_RECORD.split_at(b"data: ".len()).into();
    let mut prefix_len = 0;
    for part in parts {
        gzip.write_all(part).unwrap();
        gzip.flush().unwrap();
        let prefix = gzip.get_ref();
        stream
            .send_data(Bytes::copy_from_slice(&prefix[prefix_len..]), false)
            .unwrap();
        prefix_len = prefix.len();
    }

    // Keep the gzip trailer and END_STREAM behind the observation assertion.
    finish.notified().await;
    let wire = Bytes::from(gzip.finish().unwrap());
    stream.send_data(wire.slice(prefix_len..), true).unwrap();
}

pub(super) async fn check_live_gzip_observation() {
    let (decoded, mut chunks) = mpsc::unbounded_channel();
    let resume = Arc::new(Notify::new());
    let capture = Capture {
        probe: Some(Probe {
            decoded,
            resume: Some(resume.clone()),
        }),
        ..Capture::default()
    };
    let fixture =
        Fixture::start_with_capture(UncontrolledForwarding, 1024, Routing::Original, capture).await;
    let mut sender = fixture.sender.clone().ready().await.unwrap();
    let request = fixture.request(GZIP_PATH).body(()).unwrap();
    let requested_at = SystemTime::now();
    let (response, _) = sender.send_request(request, true).unwrap();
    let wait = Duration::from_secs(5);
    let mut body = timeout(wait, response).await.unwrap().unwrap().into_body();
    let mut wire = Vec::new();
    for _ in 0_usize..2 {
        let chunk = timeout(wait, body.data()).await.unwrap().unwrap().unwrap();
        wire.extend_from_slice(&chunk);
        body.flow_control().release_capacity(chunk.len()).unwrap();
    }
    let queued_by = SystemTime::now();
    let (at, first) = timeout(wait, chunks.recv()).await.unwrap().unwrap();
    assert_eq!(first, b"data: "[..]);
    assert!(
        (requested_at..=queued_by).contains(&at),
        "the first decoded chunk should retain its queue timestamp"
    );
    assert!(
        matches!(chunks.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the second callback must wait until the worker resumes"
    );

    // The second compressed chunk reached the client before its observer could run.
    sleep(Duration::from_millis(10)).await;
    resume.notify_one();
    let (at, second) = timeout(wait, chunks.recv()).await.unwrap().unwrap();
    assert_eq!([first.as_ref(), second.as_ref()].concat(), GZIP_RECORD);
    assert!(
        (requested_at..=queued_by).contains(&at),
        "the delayed callback should retain the earlier queue timestamp"
    );
    assert!(
        wire.starts_with(&[0x1f, 0x8b]),
        "the forwarded wire must stay gzip encoded"
    );
    assert!(!body.is_end_stream(), "the origin has not sent END_STREAM");
    assert!(
        fixture.capture.exchanges.lock().is_empty(),
        "the full exchange should still be open"
    );

    fixture.finish_gzip.notify_one();
    timeout(wait, read_body(&mut body, &mut wire))
        .await
        .unwrap();
    let captured = fixture.captured(1).await;
    assert_eq!(captured[0].response.body().raw_bytes(), wire);
    assert_eq!(captured[0].response.body().bytes(), GZIP_RECORD);
    drop(sender);
    fixture.close().await;
}
