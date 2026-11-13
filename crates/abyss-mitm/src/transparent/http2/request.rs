//! HTTP/2 authority validation and bounded pre-forward request inspection.

use std::time::Duration;

use bytes::Bytes;
use h2::RecvStream;
use http::{HeaderMap, Request, StatusCode, header};

use super::super::{
    BodyDecodingStatus, CapturedBody, FlowContext, LocalRejection, RequestForwardingControl,
    RequestTransport, RequestView, TransparentFlowError, content_encoding::ContentDecoder,
};
use super::{body::BodyCapture, error};

pub(super) struct RetainedRequest {
    pub(super) bytes: Bytes,
    pub(super) trailers: Option<HeaderMap>,
    pub(super) capture: CapturedBody,
}

pub(super) struct Http2Request<'a> {
    flow: &'a FlowContext,
    limit: usize,
}

impl<'a> Http2Request<'a> {
    pub(super) const fn new(flow: &'a FlowContext, limit: usize) -> Self {
        Self { flow, limit }
    }

    /// Bind every stream to the original TLS identity, including coalesced requests.
    /// Redirects are applied only after checking the client's original authority.
    pub(super) fn validate(&self, request: &mut Request<()>) -> Result<(), LocalRejection> {
        if request.method() == http::Method::CONNECT {
            return Err(self.reject(
                StatusCode::METHOD_NOT_ALLOWED,
                "unsupported_http2_connect",
                "HTTP/2 CONNECT is not supported",
            ));
        }
        if request.uri().scheme_str() != Some("https") {
            return Err(self.reject(
                StatusCode::BAD_REQUEST,
                "invalid_http2_scheme",
                "Expected an HTTPS request",
            ));
        }
        let Some(authority) = request.uri().authority() else {
            return Err(self.reject(
                StatusCode::BAD_REQUEST,
                "invalid_http2_authority",
                "Request authority is required",
            ));
        };
        let super::super::TransparentProtocol::TlsHttp { server_name } = &self.flow.protocol else {
            return Err(self.reject(
                StatusCode::BAD_REQUEST,
                "invalid_http2_scheme",
                "Expected a TLS connection",
            ));
        };
        let port = self
            .flow
            .ingress
            .proxy_target()
            .map(crate::TargetAuthority::port)
            .or_else(|| {
                self.flow
                    .original_destination
                    .socket_addr()
                    .map(|address| address.port())
            })
            .unwrap_or(443);
        let target = crate::TargetAuthority::from_host_port(server_name, port).map_err(|_| {
            self.reject(
                StatusCode::BAD_REQUEST,
                "invalid_http2_authority",
                "Invalid TLS authority",
            )
        })?;
        let host_matches = request.headers().get_all(header::HOST).iter().all(|host| {
            host.to_str()
                .is_ok_and(|host| target.matches_http_authority(host, 443))
        });
        if !target.matches_http_authority(authority.as_str(), 443) || !host_matches {
            return Err(self.reject(
                StatusCode::MISDIRECTED_REQUEST,
                "http2_authority_mismatch",
                "Request authority does not match the TLS destination",
            ));
        }
        // Existing Agent parsers consume Host; h2 represents :authority in the URI.
        let host = http::HeaderValue::from_str(authority.as_str()).map_err(|_| {
            self.reject(
                StatusCode::BAD_REQUEST,
                "invalid_http2_authority",
                "Invalid request authority",
            )
        })?;
        request.headers_mut().insert(header::HOST, host);
        Ok(())
    }

    pub(super) async fn inspect<C: RequestForwardingControl>(
        &self,
        head: &mut Request<()>,
        source: RecvStream,
        control: &C,
        plan: C::Plan,
    ) -> Result<RetainedRequest, LocalRejection> {
        let (mut bytes, mut trailers) = self.retain(source).await?;
        let headers = head.headers().clone();
        let mut capture = BodyCapture::new(self.limit);
        capture.append(&bytes);
        let mut capture = capture.finish(&headers);
        capture = tokio::task::spawn_blocking(move || {
            ContentDecoder::decode_body(&headers, &mut capture, false);
            capture
        })
        .await
        .map_err(|_| {
            self.reject(
                StatusCode::SERVICE_UNAVAILABLE,
                "inspection_unavailable",
                "Request decoder unavailable",
            )
        })?;
        match capture.decoding_status() {
            BodyDecodingStatus::Complete => {}
            BodyDecodingStatus::Truncated | BodyDecodingStatus::BudgetExceeded => {
                return Err(self.reject(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "inspection_body_too_large",
                    "Decoded request exceeds inspection limit",
                ));
            }
            BodyDecodingStatus::UnsupportedEncoding
            | BodyDecodingStatus::UnsupportedTransferEncoding => {
                return Err(self.reject(
                    StatusCode::UNSUPPORTED_MEDIA_TYPE,
                    "unsupported_request_encoding",
                    "Unsupported request encoding",
                ));
            }
            _ => {
                return Err(self.reject(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_encoding",
                    "Invalid request encoding",
                ));
            }
        }
        let result = control
            .before_forward(
                plan,
                RequestView {
                    flow: self.flow,
                    head,
                    body: &capture,
                    transport: RequestTransport::Http,
                },
            )
            .await?;
        if let Some(replacement) = result.head {
            *head = replacement;
        }
        if let Some(body) = result.body {
            bytes = body.bytes_ref().clone();
            trailers = None;
            capture = body;
        }
        capture.extensions_mut().extend(result.annotations);
        Ok(RetainedRequest {
            bytes,
            trailers,
            capture,
        })
    }

    async fn retain(
        &self,
        mut source: RecvStream,
    ) -> Result<(Bytes, Option<HeaderMap>), LocalRejection> {
        let read = async {
            let mut bytes = Vec::new();
            while let Some(chunk) = source.data().await {
                let chunk = chunk.map_err(|_| {
                    self.reject(
                        StatusCode::BAD_REQUEST,
                        "invalid_request_body",
                        "Incomplete or invalid request body",
                    )
                })?;
                if chunk.len() > self.limit.saturating_sub(bytes.len()) {
                    return Err(self.reject(
                        StatusCode::PAYLOAD_TOO_LARGE,
                        "inspection_body_too_large",
                        "Request exceeds inspection limit",
                    ));
                }
                bytes.extend_from_slice(&chunk);
                source
                    .flow_control()
                    .release_capacity(chunk.len())
                    .map_err(|_| {
                        self.reject(
                            StatusCode::BAD_REQUEST,
                            "invalid_request_body",
                            "Invalid request flow control",
                        )
                    })?;
            }
            let trailers = source.trailers().await.map_err(|_| {
                self.reject(
                    StatusCode::BAD_REQUEST,
                    "invalid_request_body",
                    "Invalid request trailers",
                )
            })?;
            Ok((Bytes::from(bytes), trailers))
        };
        let (bytes, trailers) = tokio::time::timeout(Duration::from_secs(30), read)
            .await
            .map_err(|_| {
                self.reject(
                    StatusCode::REQUEST_TIMEOUT,
                    "inspection_body_timeout",
                    "Request body was not completed within 30 seconds",
                )
            })??;
        Ok((bytes, trailers))
    }

    fn reject(
        &self,
        status: StatusCode,
        code: &'static str,
        message: &'static str,
    ) -> LocalRejection {
        LocalRejection::new(status, code, message, self.flow.flow_id.to_string())
    }
}

impl RetainedRequest {
    pub(super) async fn send(
        self,
        mut destination: h2::SendStream<Bytes>,
    ) -> Result<CapturedBody, TransparentFlowError> {
        super::body::send_data(&mut destination, self.bytes)
            .await
            .map_err(error)?;
        if let Some(trailers) = self.trailers {
            destination.send_trailers(trailers).map_err(error)?;
        } else {
            destination.send_data(Bytes::new(), true).map_err(error)?;
        }
        Ok(self.capture)
    }
}
