//! Connect directly to the trusted worker before transmitting catalog material.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{Method, Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde_json::Value;
use std::{path::Path, time::Duration};

pub struct Client<'a> {
    pub endpoint: &'a Path,
    pub personal: bool,
}

impl Client<'_> {
    pub fn request(
        &self,
        method: Method,
        resource: &'static str,
        body: Vec<u8>,
    ) -> Result<Value, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "Cannot initialize route control.")?;
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(15), self.send(method, resource, body))
                .await
                .map_err(|_| "Model routing service timed out.")?
        })
    }

    async fn send(
        &self,
        method: Method,
        resource: &'static str,
        body: Vec<u8>,
    ) -> Result<Value, String> {
        let stream = crate::sys::connect(self.endpoint, self.personal)
            .await
            .map_err(|_| "Model routing service unavailable.")?;
        let (mut sender, connection) = http1::handshake(TokioIo::new(stream))
            .await
            .map_err(|_| "Cannot open route control.")?;
        tokio::spawn(connection);
        let request = Request::builder()
            .method(method)
            .uri(resource)
            .header("host", "localhost")
            .header("content-type", "application/json")
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| "Invalid control request.")?;
        let response = sender
            .send_request(request)
            .await
            .map_err(|_| "Model routing service disconnected.")?;
        let status = response.status();
        let body = Limited::new(
            response.into_body(),
            usize::try_from(super::LIMIT).unwrap_or(usize::MAX),
        )
        .collect()
        .await
        .map_err(|_| "Invalid route control reply.")?;
        let value: Value =
            serde_json::from_slice(&body.to_bytes()).map_err(|_| "Invalid route control reply.")?;
        if status.is_success() {
            Ok(value)
        } else {
            Err(value["error"]
                .as_str()
                .unwrap_or("Model routing service rejected the request.")
                .to_owned())
        }
    }
}
