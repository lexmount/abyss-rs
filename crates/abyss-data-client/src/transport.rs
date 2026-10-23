//! Bounded synchronous JSON transport shared by data queries and terminal auth.

use std::{io::Read as _, time::Duration};

use reqwest::{
    Method, Url,
    blocking::Client,
    header::{AUTHORIZATION, HeaderValue, RETRY_AFTER},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::DataClientError;

/// HTTP client with explicit deadlines, bounded bodies and no redirects.
pub struct HttpTransport {
    client: Client,
    max_response_bytes: usize,
    retries: u8,
}

impl HttpTransport {
    /// Builds a transport. A custom PEM certificate extends normal TLS trust.
    ///
    /// # Errors
    /// Returns an error for invalid budgets, certificates or client configuration.
    pub fn new(
        timeout: Duration,
        max_response_bytes: usize,
        ca_pem: Option<&[u8]>,
        retries: u8,
    ) -> Result<Self, DataClientError> {
        if timeout.is_zero()
            || timeout > Duration::from_secs(600)
            || !(1024..=64 * 1024 * 1024).contains(&max_response_bytes)
            || retries > 3
        {
            return Err(DataClientError::Configuration(
                "timeout must be positive and at most 600s, response budget 1KiB..64MiB, retries 0..3",
            ));
        }
        let mut builder = Client::builder()
            .timeout(timeout)
            .connect_timeout(timeout.min(Duration::from_secs(10)))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("abyss-query/", env!("CARGO_PKG_VERSION")));
        if let Some(pem) = ca_pem {
            let certificates = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|_| DataClientError::Configuration("invalid CA PEM bundle"))?;
            if certificates.is_empty() {
                return Err(DataClientError::Configuration("CA PEM bundle is empty"));
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        let client = builder.build().map_err(DataClientError::Transport)?;
        Ok(Self {
            client,
            max_response_bytes,
            retries,
        })
    }

    /// Sends one read-only request with a bounded number of transient retries.
    ///
    /// # Errors
    /// Returns sanitized transport, HTTP, size or decoding errors.
    pub fn get<R: DeserializeOwned>(
        &self,
        url: &Url,
        bearer: Option<&str>,
    ) -> Result<R, DataClientError> {
        self.send(&Method::GET, url, bearer, Option::<&()>::None)
    }

    /// Sends a JSON POST exactly once. Intended for explicit authentication flows.
    ///
    /// # Errors
    /// Returns sanitized transport, HTTP, size or decoding errors.
    pub fn post<R: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        url: &Url,
        bearer: Option<&str>,
        body: &B,
    ) -> Result<R, DataClientError> {
        self.send(&Method::POST, url, bearer, Some(body))
    }

    fn send<R: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        method: &Method,
        url: &Url,
        bearer: Option<&str>,
        body: Option<&B>,
    ) -> Result<R, DataClientError> {
        let auth = bearer.map(Self::authorization).transpose()?;
        let retries = if *method == Method::GET {
            self.retries
        } else {
            0
        };
        for attempt in 0..=retries {
            let mut builder = self
                .client
                .request(method.clone(), url.clone())
                .header("accept", "application/json");
            if let Some(value) = &auth {
                builder = builder.header(AUTHORIZATION, value);
            }
            if let Some(body) = body {
                builder = builder.json(body);
            }
            let response = match builder.send() {
                Ok(response) => response,
                Err(error) if attempt < retries && (error.is_connect() || error.is_timeout()) => {
                    std::thread::sleep(Duration::from_millis(
                        200_u64.saturating_mul(u64::from(attempt).saturating_add(1)),
                    ));
                    continue;
                }
                Err(error) => return Err(DataClientError::Transport(error.without_url())),
            };
            let status = response.status().as_u16();
            if !response.status().is_success() {
                if attempt < retries
                    && matches!(status, 429 | 502 | 503 | 504)
                    && let Some(delay) =
                        Self::retry_delay(response.headers().get(RETRY_AFTER), attempt)
                {
                    drop(response);
                    std::thread::sleep(delay);
                    continue;
                }
                return Err(DataClientError::Http { status });
            }
            if response.content_length().is_some_and(|length| {
                length > u64::try_from(self.max_response_bytes).unwrap_or(u64::MAX)
            }) {
                return Err(DataClientError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                });
            }
            let mut bytes = Vec::new();
            response
                .take(
                    u64::try_from(self.max_response_bytes)
                        .unwrap_or(u64::MAX)
                        .saturating_add(1),
                )
                .read_to_end(&mut bytes)
                .map_err(DataClientError::Read)?;
            if bytes.len() > self.max_response_bytes {
                return Err(DataClientError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                });
            }
            return serde_json::from_slice(&bytes).map_err(DataClientError::Decode);
        }
        unreachable!("bounded request loop always returns on its last attempt")
    }

    fn authorization(token: &str) -> Result<HeaderValue, DataClientError> {
        if token.is_empty() || token.chars().any(char::is_whitespace) {
            return Err(DataClientError::Configuration(
                "bearer token must be nonempty and contain no whitespace",
            ));
        }
        let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| DataClientError::Configuration("invalid bearer token"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn retry_delay(header: Option<&HeaderValue>, attempt: u8) -> Option<Duration> {
        let Some(header) = header else {
            return Some(Duration::from_millis(
                200_u64.saturating_mul(u64::from(attempt).saturating_add(1)),
            ));
        };
        let value = header.to_str().ok()?;
        let delay = if let Ok(seconds) = value.parse::<u64>() {
            Duration::from_secs(seconds)
        } else {
            chrono::DateTime::parse_from_rfc2822(value)
                .ok()?
                .with_timezone(&chrono::Utc)
                .signed_duration_since(chrono::Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO)
        };
        (delay <= Duration::from_secs(5)).then_some(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::HttpTransport;
    use reqwest::header::HeaderValue;
    use std::time::Duration;
    #[test]
    fn bounded_retry_after_and_sensitive_authorization() {
        assert_eq!(
            HttpTransport::retry_delay(Some(&HeaderValue::from_static("3")), 0),
            Some(Duration::from_secs(3)),
            "honor short retry-after"
        );
        assert!(
            HttpTransport::retry_delay(Some(&HeaderValue::from_static("600")), 0).is_none(),
            "do not retry earlier than server's long delay"
        );
        assert!(
            HttpTransport::retry_delay(Some(&HeaderValue::from_static("nonsense")), 0).is_none(),
            "reject malformed delay"
        );
        assert!(
            HttpTransport::authorization("token")
                .expect("token")
                .is_sensitive(),
            "redact header debug"
        );
        for token in ["", "a b", "a\r\nb"] {
            assert!(
                HttpTransport::authorization(token).is_err(),
                "reject malformed token"
            );
        }
    }
}
