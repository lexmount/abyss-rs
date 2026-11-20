//! Read one credential's model list from its configured API origin.
use std::{collections::BTreeSet, time::Duration};

use http_body_util::{BodyExt as _, Limited};
use reqwest::{Client, Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{Catalog, Credential, ServiceCredential};

#[derive(Deserialize)]
pub struct ModelListRequest {
    provider: String,
    credential: String,
    #[serde(default)]
    pub include_metadata: bool,
}

#[derive(Deserialize)]
struct Model {
    id: String,
    #[serde(default)]
    created: Value,
    #[serde(default)]
    created_at: Value,
}

#[derive(Serialize)]
pub struct ListedModel {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<i64>,
}

impl From<Model> for ListedModel {
    fn from(model: Model) -> Self {
        let created = model
            .created_at
            .as_str()
            .and_then(|text| text.parse::<jiff::Timestamp>().ok())
            .map(jiff::Timestamp::as_second)
            .or_else(|| model.created.as_i64())
            .filter(|seconds| *seconds > 0);
        Self {
            id: model.id,
            created,
        }
    }
}

#[derive(Deserialize)]
struct Page {
    data: Vec<Model>,
    #[serde(default)]
    has_more: bool,
    last_id: Option<String>,
}

fn endpoint(base: &str) -> Result<Url, &'static str> {
    let mut url = crate::catalog::https_url(base)?;
    let path = url.path().trim_end_matches('/');
    let path = match (url.host_str(), path) {
        (Some("api.deepseek.com"), "" | "/v1" | "/anthropic") => "/models".to_owned(),
        (_, path) if path.ends_with("/anthropic") => format!("{path}/v1/models"),
        (_, "") => "/v1/models".to_owned(),
        _ => format!("{path}/models"),
    };
    url.set_path(&path);
    Ok(url)
}

impl Catalog {
    pub async fn list_models(
        &self,
        selection: &ModelListRequest,
    ) -> Result<Vec<ListedModel>, &'static str> {
        if !self
            .harness_providers
            .values()
            .any(|ids| ids.contains(&selection.provider))
        {
            return Err("Provider is unavailable.");
        }
        let (provider, credential) =
            self.provider_credential(&selection.provider, &selection.credential)?;
        if credential.authentication().is_none() {
            return Err("Credential unavailable.");
        }
        if !provider.models.is_empty() {
            return Ok(provider
                .models
                .iter()
                .map(|id| ListedModel {
                    id: id.clone(),
                    created: None,
                })
                .collect());
        }
        let base = provider
            .endpoint(&selection.provider)?
            .ok_or("Provider endpoint unavailable.")?;
        let url = endpoint(base)?;
        let client = Client::builder()
            .timeout(Duration::from_secs(8))
            .redirect(Policy::none())
            .build()
            .map_err(|_| "Cannot initialize model list client.")?;
        fetch(
            &client,
            &url,
            credential,
            selection.provider == "anthropic" || url.path().contains("/anthropic/"),
        )
        .await
    }
}

async fn fetch(
    client: &Client,
    url: &Url,
    credential: &Credential,
    anthropic: bool,
) -> Result<Vec<ListedModel>, &'static str> {
    let mut models = Vec::new();
    let mut seen = BTreeSet::new();
    let mut cursors = BTreeSet::new();
    let mut cursor = None;
    loop {
        let mut request = client.get(url.clone()).header("Accept", "application/json");
        if anthropic {
            request = request.header("anthropic-version", "2023-06-01");
        }
        request = match credential {
            Credential::Service(ServiceCredential::ApiKey { api_key })
                if !api_key.trim().is_empty() =>
            {
                if url.host_str() == Some("api.anthropic.com") {
                    request.header("x-api-key", api_key)
                } else {
                    request.bearer_auth(api_key)
                }
            }
            Credential::ExplicitHeaders { headers, .. }
                if credential.authentication().is_some() =>
            {
                for (name, value) in headers {
                    request = request.header(name, value);
                }
                request
            }
            _ => return Err("Credential unavailable."),
        };
        if let Some(after) = cursor.as_ref() {
            request = request.query(&[("after_id", after)]);
        }
        let response = request
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|_| "The provider model list is unavailable.")?;
        let body = Limited::new(reqwest::Body::from(response), 4 * 1024 * 1024)
            .collect()
            .await
            .map_err(|_| "Invalid provider model list.")?;
        let page: Page =
            serde_json::from_slice(&body.to_bytes()).map_err(|_| "Invalid provider model list.")?;
        for model in page.data {
            if super::valid_model_id(&model.id) && seen.insert(model.id.clone()) {
                models.push(model.into());
            }
        }
        if !page.has_more {
            return Ok(models);
        }
        let last = page
            .last_id
            .filter(|v| !v.is_empty() && cursors.insert(v.clone()))
            .ok_or("Invalid model list pagination.")?;
        cursor = Some(last);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn reads_every_page_in_provider_order_with_the_selected_credential() {
        use std::{
            io::{BufRead as _, BufReader, Write as _},
            net::TcpListener,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = Url::parse(&format!(
            "http://{}/custom/v1/models",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let server = std::thread::spawn(move || {
            for (path, body) in [
                (
                    "/custom/v1/models",
                    r#"{"data":[{"id":"zulu","created":1767225600},{"id":"alpha","created_at":"2026-02-01T01:00:00+01:00"}],"has_more":true,"last_id":"alpha"}"#,
                ),
                (
                    "/custom/v1/models?after_id=alpha",
                    r#"{"data":[{"id":"alpha"},{"id":"next","created":"unavailable"}],"has_more":false}"#,
                ),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let headers: Vec<_> = BufReader::new(&stream)
                    .lines()
                    .map(Result::unwrap)
                    .take_while(|line| !line.is_empty())
                    .collect();
                assert_eq!(headers[0], format!("GET {path} HTTP/1.1"));
                assert!(
                    headers
                        .iter()
                        .any(|line| line.eq_ignore_ascii_case("Authorization: Bearer fixture"))
                );
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            }
        });
        let auth = Credential::Service(ServiceCredential::ApiKey {
            api_key: "fixture".into(),
        });
        let client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        assert_eq!(
            serde_json::to_value(fetch(&client, &url, &auth, true).await.unwrap()).unwrap(),
            serde_json::json!([
                {"id":"zulu", "created":1_767_225_600_i64},
                {"id":"alpha", "created":1_769_904_000_i64},
                {"id":"next"}
            ])
        );
        server.join().unwrap();
    }

    #[test]
    fn discovery_retains_the_configured_origin_and_api_prefix() {
        for (base, path) in [
            ("https://api.deepseek.com/anthropic", "/models"),
            (
                "https://open.bigmodel.cn/api/anthropic",
                "/api/anthropic/v1/models",
            ),
            ("https://api.minimax.cn/anthropic", "/anthropic/v1/models"),
            (
                "https://dashscope.aliyuncs.com/compatible-mode/v1/",
                "/compatible-mode/v1/models",
            ),
            ("https://api.moonshot.cn/v1", "/v1/models"),
            ("https://api.openai.com/v1", "/v1/models"),
            ("https://relay.example/prefix/v1", "/prefix/v1/models"),
        ] {
            let target = endpoint(base).unwrap();
            assert_eq!(target.origin(), Url::parse(base).unwrap().origin());
            assert_eq!(target.path(), path);
        }
    }
}
