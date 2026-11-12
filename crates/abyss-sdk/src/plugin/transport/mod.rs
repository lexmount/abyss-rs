//! Platform-local stream connection used by the plugin runtime.

use std::{io, pin::Pin};

use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(test)]
mod tests;

pub(super) trait PluginStream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T> PluginStream for T where T: AsyncRead + AsyncWrite + Send + Unpin {}

pub(super) type ConnectedPluginStream = Pin<Box<dyn PluginStream>>;

/// HTTP upgrade is restricted to loopback and never follows redirects or proxies.
pub(super) async fn connect_http(origin: &str, token: &str) -> io::Result<ConnectedPluginStream> {
    let mut url =
        reqwest::Url::parse(origin).map_err(|_| io::Error::other("invalid broker API origin"))?;
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    if url.scheme() != "http"
        || !local
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(io::Error::other(
            "plugin API requires a loopback HTTP origin",
        ));
    }
    url.set_path("/v1/plugins/connect");
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|_| io::Error::other("plugin HTTP client unavailable"))?;
    let response = client
        .post(url)
        .bearer_auth(token)
        .header("Connection", "upgrade")
        .header("Upgrade", "abyss-plugin-v1")
        .send()
        .await
        .map_err(|_| io::Error::other("plugin API connection failed"))?;
    if response.status() != reqwest::StatusCode::SWITCHING_PROTOCOLS
        || response
            .headers()
            .get("Upgrade")
            .and_then(|value| value.to_str().ok())
            != Some("abyss-plugin-v1")
    {
        return Err(io::Error::other("plugin API upgrade rejected"));
    }
    let stream = response
        .upgrade()
        .await
        .map_err(|_| io::Error::other("plugin API upgrade failed"))?;
    Ok(Box::pin(stream))
}

#[cfg(unix)]
pub(super) async fn connect(endpoint: &str) -> io::Result<ConnectedPluginStream> {
    let stream = tokio::net::UnixStream::connect(endpoint).await?;
    let stream: ConnectedPluginStream = Box::pin(stream);
    Ok(stream)
}

#[cfg(target_os = "windows")]
pub(super) fn connect(endpoint: &str) -> std::future::Ready<io::Result<ConnectedPluginStream>> {
    let connected = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(endpoint)
        .map(|stream| {
            let stream: ConnectedPluginStream = Box::pin(stream);
            stream
        });
    std::future::ready(connected)
}
