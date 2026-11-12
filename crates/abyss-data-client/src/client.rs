//! Public backend operations; no profile or credential persistence.

use std::time::Duration;

use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::{
    ApiEndpoint, DataClientError, HttpTransport,
    models::{
        ConversationPreview, EventLocation, EventPage, SearchPage, Segment, SessionHeader,
        SessionPage, SessionSearch, SessionStreams, SessionTurns, UsageEvent, UsageSummary,
    },
    query::{EventQuery, PageQuery, PreviewQuery, SummaryQuery},
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

    /// Reads a session page header.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn session_header(&self, id: Uuid) -> Result<SessionHeader, DataClientError> {
        self.get(&["sessions", &id.to_string(), "header"], &[])
    }

    /// Creates a session snapshot using the server's existing sharing policy.
    /// This non-idempotent POST is sent once, even with GET retries configured.
    ///
    /// # Errors
    /// Returns authorization, unsupported-route, transport or protocol errors.
    /// A transport failure may occur after creation; do not blindly retry.
    pub fn create_session_share(
        &self,
        id: Uuid,
    ) -> Result<crate::models::CreatedSessionShare, DataClientError> {
        let url =
            self.endpoint
                .resource(&["v1", "agent-usage", "sessions", &id.to_string(), "shares"]);
        self.transport.post(&url, self.bearer.as_deref(), &())
    }

    /// Reads a session's segments.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn session_streams(&self, id: Uuid) -> Result<SessionStreams, DataClientError> {
        self.get(&["sessions", &id.to_string(), "streams"], &[])
    }

    /// Reads a session's turn tree.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn session_turns(&self, id: Uuid) -> Result<SessionTurns, DataClientError> {
        self.get(&["sessions", &id.to_string(), "turns"], &[])
    }

    /// Reads one segment's exchanges.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn segment(
        &self,
        id: Uuid,
        head: &str,
        query: &PreviewQuery,
    ) -> Result<Segment, DataClientError> {
        if head.is_empty() {
            return Err(DataClientError::Query("segment head must not be empty"));
        }
        self.get(
            &["sessions", &id.to_string(), "segments", head],
            &query.pairs(),
        )
    }

    /// Searches one session's content when the server supports literal search.
    ///
    /// # Errors
    /// Returns query, transport or protocol errors.
    pub fn search_session(&self, id: Uuid, text: &str) -> Result<SessionSearch, DataClientError> {
        if text.trim().is_empty() {
            return Err(DataClientError::Query("search text must not be empty"));
        }
        self.get(
            &["sessions", &id.to_string(), "search"],
            &[("q".into(), text.into())],
        )
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

    /// Previews one event's conversation entries.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn conversation(
        &self,
        id: Uuid,
        query: &PreviewQuery,
    ) -> Result<ConversationPreview, DataClientError> {
        self.get(&["events", &id.to_string(), "conversation"], &query.pairs())
    }

    /// Reads where one event sits in its session.
    ///
    /// # Errors
    /// Returns transport or protocol errors.
    pub fn event_location(&self, id: Uuid) -> Result<EventLocation, DataClientError> {
        self.get(&["events", &id.to_string(), "location"], &[])
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
