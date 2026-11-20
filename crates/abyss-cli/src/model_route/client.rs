//! Connect directly to the trusted worker before transmitting catalog material.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{Method, Request, client::conn::http1};
use hyper_util::rt::TokioIo;
use nix::unistd::Uid;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

pub(super) struct Client {
    endpoint: PathBuf,
    runtime: tokio::runtime::Runtime,
}

impl Client {
    pub(super) fn new(profile: &Path) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| "Cannot initialize route control.")?;
        Ok(Self {
            endpoint: personal_endpoint(profile),
            runtime,
        })
    }

    pub(super) fn endpoint(&self) -> &Path {
        &self.endpoint
    }

    pub(super) fn request(
        &self,
        method: Method,
        resource: &'static str,
        body: Vec<u8>,
    ) -> Result<Value, String> {
        self.runtime.block_on(async {
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
        let stream = tokio::net::UnixStream::connect(&self.endpoint)
            .await
            .map_err(|_| "Model routing service unavailable.")?;
        if stream
            .peer_cred()
            .map_err(|_| "Cannot identify routing service.")?
            .uid()
            != Uid::effective().as_raw()
        {
            return Err("Unexpected routing service owner.".into());
        }
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
        let body = Limited::new(response.into_body(), 4 * 1024 * 1024)
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

fn personal_endpoint(profile: &Path) -> PathBuf {
    use sha2::{Digest as _, Sha256};
    let path = profile.with_extension("sock");
    if path.as_os_str().as_encoded_bytes().len() < 100 {
        return path;
    }
    // Peer credentials authenticate the service even for the short path required
    // by sockaddr_un. Include the owner to separate independent CLI installations.
    let digest = Sha256::digest(path.as_os_str().as_encoded_bytes());
    PathBuf::from(format!(
        "/tmp/abyss-route-{}-{digest:x}.sock",
        Uid::effective()
    ))
}
