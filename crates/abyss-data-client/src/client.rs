//! Read-only public backend operations; no profile or credential persistence.

use std::time::Duration;

use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::{
    ApiEndpoint, DataClientError, HttpTransport,
    models::{
        EventPage, SearchPage, SessionPage, SessionTimeline, SessionTrajectory, UsageEvent,
        UsageSummary,
    },
    query::{EventQuery, PageQuery, SummaryQuery},
};

/// Transport budgets for a data client.
pub struct DataClientOptions {
    /// Per-attempt deadline, including reading the body.
    pub timeout: Duration,
    /// Maximum decompressed JSON response size.
    pub max_response_bytes: usize,
    /// Additional trusted certificates, PEM encoded.
    pub ca_pem: Option<Vec<u8>>,
    /// Transient GET retries, at most three.
    pub retries: u8,
}

impl Default for DataClientOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_response_bytes: 8 * 1024 * 1024,
            ca_pem: None,
            retries: 2,
        }
    }
}

/// Client for the shared `SaaS` and standalone HTTP data contract.
pub struct DataClient {
    endpoint: ApiEndpoint,
    bearer: Option<String>,
    transport: HttpTransport,
}

impl DataClient {
    /// Creates a client without network access. `None` means anonymous access.
    ///
    /// # Errors
    /// Returns an error for invalid transport options or CA certificates.
    pub fn new(
        endpoint: ApiEndpoint,
        bearer: Option<String>,
        options: &DataClientOptions,
    ) -> Result<Self, DataClientError> {
        let transport = HttpTransport::new(
            options.timeout,
            options.max_response_bytes,
            options.ca_pem.as_deref(),
            options.retries,
        )?;
        Ok(Self {
            endpoint,
            bearer,
            transport,
        })
    }

    /// Lists a bounded page of sessions.
    ///
    /// # Errors
    /// Returns query, transport or protocol errors.
    pub fn sessions(&self, query: &PageQuery) -> Result<SessionPage, DataClientError> {
        self.get(&["sessions"], &query.pairs()?)
    }

    /// Searches indexed session content. Disabled search remains an HTTP error.
    ///
    /// # Errors
    /// Returns query, transport or protocol errors.
    pub fn search(&self, text: &str, query: &PageQuery) -> Result<SearchPage, DataClientError> {
        if text.trim().is_empty() {
            return Err(DataClientError::Query("search text must not be empty"));
        }
        let mut pairs = query.pairs()?;
        pairs.push(("q".into(), text.into()));
        self.get(&["search"], &pairs)
    }

    /// Reads a complete session timeline.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn session(&self, id: Uuid) -> Result<SessionTimeline, DataClientError> {
        self.get(&["sessions", &id.to_string()], &[])
    }

    /// Reads a session's compact outline, preserving omitted content.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn outline(&self, id: Uuid) -> Result<SessionTimeline, DataClientError> {
        self.get(&["sessions", &id.to_string(), "outline"], &[])
    }

    /// Reads the backend's normalized trajectory.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn trajectory(&self, id: Uuid) -> Result<SessionTrajectory, DataClientError> {
        self.get(&["sessions", &id.to_string(), "trajectory"], &[])
    }

    /// Lists persisted events, using a decimal offset as continuation token.
    ///
    /// # Errors
    /// Returns query, transport or protocol errors.
    pub fn events(&self, query: &EventQuery) -> Result<EventPage, DataClientError> {
        self.get(&["events"], &query.pairs()?)
    }

    /// Reads one persisted event by backend primary key.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn event(&self, id: Uuid) -> Result<UsageEvent, DataClientError> {
        self.get(&["events", &id.to_string()], &[])
    }

    /// Reads usage aggregation. Scope authorization remains server-owned.
    ///
    /// # Errors
    /// Returns query, transport or protocol errors.
    pub fn summary(&self, query: &SummaryQuery) -> Result<UsageSummary, DataClientError> {
        self.get(&["summary"], &query.pairs()?)
    }

    fn get<R: DeserializeOwned>(
        &self,
        resource: &[&str],
        pairs: &[(String, String)],
    ) -> Result<R, DataClientError> {
        let mut segments = vec!["v1", "agent-usage"];
        segments.extend_from_slice(resource);
        let mut url = self.endpoint.resource(&segments);
        if !pairs.is_empty() {
            url.query_pairs_mut().extend_pairs(pairs);
        }
        self.transport.get(&url, self.bearer.as_deref())
    }
}
