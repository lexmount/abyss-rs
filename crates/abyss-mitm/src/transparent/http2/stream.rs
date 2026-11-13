//! One independent HTTP/2 exchange, including inspection and local rejections.

use bytes::Bytes;
use h2::{RecvStream, client::SendRequest, server::SendResponse};
use http::{Request, Response};

use super::super::{HttpExchange, LocalRejection, RequestForwardingControl, TransparentFlowError};
use super::{
    Http2Relay,
    body::BodyCapture,
    error,
    request::{Http2Request, RetainedRequest},
};

enum RequestBody {
    Streaming(RecvStream),
    Retained(Box<RetainedRequest>),
}

impl<C: RequestForwardingControl> Http2Relay<'_, C> {
    pub(super) async fn exchange(
        &self,
        request: Request<RecvStream>,
        mut respond: SendResponse<Bytes>,
        upstream: SendRequest<Bytes>,
    ) -> Option<HttpExchange> {
        match self.forward(request, &mut respond, upstream).await {
            Ok(exchange) => Some(exchange),
            Err(TransparentFlowError::Rejected(rejection)) => {
                if let Err(error) = reject(&mut respond, &rejection).await {
                    tracing::debug!(%error, "HTTP/2 local rejection could not be delivered");
                }
                None
            }
            Err(error) => {
                tracing::debug!(%error, "HTTP/2 stream relay failed");
                let reason = match &error {
                    TransparentFlowError::Io { source, .. } => source
                        .get_ref()
                        .and_then(|source| source.downcast_ref::<h2::Error>())
                        .and_then(h2::Error::reason)
                        .unwrap_or(h2::Reason::CANCEL),
                    _ => h2::Reason::CANCEL,
                };
                // REFUSED_STREAM tells clients that a request was not processed and
                // can be retried, unlike a generic cancellation.
                respond.send_reset(reason);
                None
            }
        }
    }

    async fn forward(
        &self,
        request: Request<RecvStream>,
        respond: &mut SendResponse<Bytes>,
        upstream: SendRequest<Bytes>,
    ) -> Result<HttpExchange, TransparentFlowError> {
        let (parts, body) = request.into_parts();
        let mut head = Request::from_parts(parts, ());
        let validator = Http2Request::new(&self.context, self.engine.max_http1_body_bytes);
        validator.validate(&mut head)?;
        if let Some(redirect) = self.redirect {
            redirect.apply(&mut head)?;
        }
        if super::super::utils::has_expect_continue(&head) {
            let response = Response::builder()
                .status(http::StatusCode::CONTINUE)
                .version(http::Version::HTTP_2)
                .body(())
                .expect("static continue response");
            respond.send_informational(response).map_err(error)?;
        }
        let body = if let Some(plan) = self.control.plan() {
            RequestBody::Retained(Box::new(
                validator
                    .inspect(&mut head, body, self.control, plan)
                    .await?,
            ))
        } else {
            RequestBody::Streaming(body)
        };
        // Continue was handled locally before any inspection retained the body.
        head.headers_mut().remove(http::header::EXPECT);
        let mut upstream =
            ready_upstream(upstream, respond, self.engine.timeouts.http1_response_head).await?;
        let (response, request_stream) =
            upstream.send_request(head.clone(), false).map_err(error)?;
        let upload = async {
            match body {
                RequestBody::Retained(retained) => retained.send(request_stream).await,
                RequestBody::Streaming(body) => BodyCapture::new(self.engine.max_http1_body_bytes)
                    .relay(body, request_stream, head.headers())
                    .await
                    .map_err(error),
            }
        };
        let download = async {
            let response =
                receive_response(respond, response, self.engine.timeouts.http1_response_head)
                    .await?;
            let (parts, body) = response.into_parts();
            let response_head = Response::from_parts(parts, ());
            let downstream = respond
                .send_response(response_head.clone(), false)
                .map_err(error)?;
            let capture = BodyCapture::new(self.engine.max_http1_body_bytes)
                .relay(body, downstream, response_head.headers())
                .await
                .map_err(error)?;
            Ok::<_, TransparentFlowError>(response_head.map(|()| capture))
        };
        // Upload and download progress independently: early responses and streaming
        // APIs must not wait for the entire request body to finish uploading.
        let (capture, response) = tokio::try_join!(upload, download)?;
        let exchange = HttpExchange {
            flow: self.context.clone(),
            request: head.map(|()| capture),
            response,
        };
        self.engine.hooks.submit(exchange.clone());
        Ok(exchange)
    }
}

async fn reject(
    respond: &mut SendResponse<Bytes>,
    rejection: &LocalRejection,
) -> Result<(), h2::Error> {
    let body = serde_json::json!({"error": {
        "source": "abyss-broker", "code": rejection.code, "message": rejection.reason,
        "request_id": rejection.request_id, "rule_id": rejection.rule_id,
    }})
    .to_string();
    let response = Response::builder()
        .status(rejection.status)
        .version(http::Version::HTTP_2)
        .header("server", "abyss-broker")
        .header("x-abyss-blocked", "true")
        .header("cache-control", "no-store")
        .header("content-type", "application/json")
        .header("content-length", body.len())
        .body(())
        .expect("static local response headers are valid");
    let mut stream = respond.send_response(response, false)?;
    super::body::send_data(&mut stream, Bytes::from(body)).await?;
    stream.send_data(Bytes::new(), true)
}

/// Drive informational headers and resets while waiting for the final response.
async fn receive_response(
    respond: &mut SendResponse<Bytes>,
    mut response: h2::client::ResponseFuture,
    timeout: std::time::Duration,
) -> Result<Response<RecvStream>, TransparentFlowError> {
    use std::{
        future::{Future as _, poll_fn},
        pin::Pin,
        task::Poll,
    };
    tokio::time::timeout(
        timeout,
        poll_fn(|cx| {
            if let Poll::Ready(reset) = respond.poll_reset(cx) {
                return Poll::Ready(Err(reset
                    .err()
                    .unwrap_or_else(|| h2::Reason::CANCEL.into())));
            }
            while let Poll::Ready(Some(informational)) = response.poll_informational(cx) {
                respond.send_informational(informational?)?;
            }
            Pin::new(&mut response).poll(cx)
        }),
    )
    .await
    .map_err(|_| TransparentFlowError::Timeout {
        operation: super::super::FlowOperation::ReadProviderResponseHead,
        timeout,
    })?
    .map_err(error)
}

/// A saturated origin must not retain canceled client streams indefinitely.
async fn ready_upstream(
    mut upstream: SendRequest<Bytes>,
    respond: &mut SendResponse<Bytes>,
    timeout: std::time::Duration,
) -> Result<SendRequest<Bytes>, TransparentFlowError> {
    use std::{future::poll_fn, task::Poll};
    tokio::time::timeout(
        timeout,
        poll_fn(|cx| {
            if let Poll::Ready(reset) = respond.poll_reset(cx) {
                return Poll::Ready(Err(reset
                    .err()
                    .unwrap_or_else(|| h2::Reason::CANCEL.into())));
            }
            upstream.poll_ready(cx)
        }),
    )
    .await
    .map_err(|_| TransparentFlowError::Timeout {
        operation: super::super::FlowOperation::WriteProviderRequestHead,
        timeout,
    })?
    .map_err(error)?;
    Ok(upstream)
}
