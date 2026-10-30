//! Typed query selectors serialized as repeated HTTP query parameters.

use crate::DataClientError;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Exact filters shared by list, search and summary endpoints.
#[derive(Default, Clone, Deserialize, Serialize, JsonSchema)]
pub struct Filters {
    /// Inclusive lower time bound.
    pub from: Option<DateTime<Utc>>,
    /// Exclusive upper time bound.
    pub to: Option<DateTime<Utc>>,
    /// Exact Agent names, OR within this dimension.
    pub agents: Vec<String>,
    /// Exact provider names.
    pub providers: Vec<String>,
    /// Exact model names.
    pub models: Vec<String>,
}

impl Filters {
    pub(crate) fn pairs(&self) -> Result<Vec<(String, String)>, DataClientError> {
        if let (Some(from), Some(to)) = (self.from, self.to)
            && from >= to
        {
            return Err(DataClientError::Query("from must be earlier than to"));
        }
        let mut pairs = Vec::new();
        if let Some(from) = self.from {
            pairs.push(("from".into(), from.to_rfc3339()));
        }
        if let Some(to) = self.to {
            pairs.push(("to".into(), to.to_rfc3339()));
        }
        for (name, values) in [
            ("agent_name", &self.agents),
            ("llm_provider", &self.providers),
            ("llm_model", &self.models),
        ] {
            for value in values {
                if value.trim().is_empty() {
                    return Err(DataClientError::Query("exact filters must not be empty"));
                }
                pairs.push((name.into(), value.clone()));
            }
        }
        Ok(pairs)
    }
}

/// One-based page window for sessions and search.
#[derive(Clone)]
pub struct PageQuery {
    /// Shared filters.
    pub filters: Filters,
    /// One-based page.
    pub page: u32,
    /// Page size, 1 through 100.
    pub page_size: u32,
}

impl Default for PageQuery {
    fn default() -> Self {
        Self {
            filters: Filters::default(),
            page: 1,
            page_size: 20,
        }
    }
}

impl PageQuery {
    pub(crate) fn pairs(&self) -> Result<Vec<(String, String)>, DataClientError> {
        if self.page == 0 || !(1..=100).contains(&self.page_size) {
            return Err(DataClientError::Query(
                "page must be positive and page_size must be 1..100",
            ));
        }
        let mut pairs = self.filters.pairs()?;
        pairs.extend([
            ("page".into(), self.page.to_string()),
            ("page_size".into(), self.page_size.to_string()),
        ]);
        Ok(pairs)
    }
}

/// Request or response event selector.
#[derive(Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventSide {
    Request,
    Response,
}

impl EventSide {
    /// Returns the query-string representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// Whether list results include content.
#[derive(Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum EventFields {
    #[default]
    List,
    Full,
}

/// Offset-based persisted-event query.
#[derive(Clone)]
pub struct EventQuery {
    /// Shared filters.
    pub filters: Filters,
    /// Agent-native session IDs.
    pub session_ids: Vec<String>,
    /// Backend session primary key.
    pub session_pk: Option<Uuid>,
    /// Normalized turn number; a filter of the `SaaS` data service.
    pub turn_index: Option<i32>,
    /// Event side.
    pub side: Option<EventSide>,
    /// Projection; defaults to content-free lists.
    pub fields: EventFields,
    /// Adds each event's current location; a standalone-backend option.
    pub locate: bool,
    /// Page size, bounded by the client to 1000.
    pub limit: u32,
    /// Number of newest events to skip.
    pub offset: u64,
}

impl Default for EventQuery {
    fn default() -> Self {
        Self {
            filters: Filters::default(),
            session_ids: Vec::new(),
            session_pk: None,
            turn_index: None,
            side: None,
            fields: EventFields::List,
            locate: false,
            limit: 20,
            offset: 0,
        }
    }
}

impl EventQuery {
    pub(crate) fn pairs(&self) -> Result<Vec<(String, String)>, DataClientError> {
        if !(1..=1000).contains(&self.limit) || self.offset > i64::MAX.unsigned_abs() {
            return Err(DataClientError::Query(
                "event limit must be 1..1000 and offset must fit a signed 64-bit integer",
            ));
        }
        let mut pairs = self.filters.pairs()?;
        for value in &self.session_ids {
            pairs.push(("session_id".into(), value.clone()));
        }
        if let Some(id) = self.session_pk {
            pairs.push(("session_pk".into(), id.to_string()));
        }
        if let Some(index) = self.turn_index {
            pairs.push(("turn_index".into(), index.to_string()));
        }
        if let Some(side) = self.side {
            pairs.push(("event_type".into(), side.as_str().into()));
        }
        let fields = match self.fields {
            EventFields::List => "list",
            EventFields::Full => "full",
        };
        pairs.extend([
            ("fields".into(), fields.into()),
            ("limit".into(), self.limit.to_string()),
            ("offset".into(), self.offset.to_string()),
        ]);
        if self.locate {
            pairs.push(("locate".into(), "true".into()));
        }
        Ok(pairs)
    }
}

/// Entry selection for conversation previews and segment exchanges.
#[derive(Clone, Default)]
pub struct PreviewQuery {
    /// Comma-separated entry runs (`a-b`, `-n`, `a`); all entries when absent.
    /// The backend validates the syntax.
    pub entries: Option<String>,
    /// Most UTF-16 code units kept of each entry text; whole texts when absent.
    pub text_preview: Option<u32>,
}

impl PreviewQuery {
    pub(crate) fn pairs(&self) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        if let Some(entries) = &self.entries {
            pairs.push(("entries".into(), entries.clone()));
        }
        if let Some(limit) = self.text_preview {
            pairs.push(("text_preview".into(), limit.to_string()));
        }
        pairs
    }
}

/// Aggregation query. Authorization of global scope is exclusively server-owned.
#[derive(Default)]
pub struct SummaryQuery {
    /// Shared filters.
    pub filters: Filters,
    /// Comma-separated dimensions accepted by the backend.
    pub group_by: Vec<String>,
    /// Explicit `SaaS` global scope; omitted for ordinary/standalone requests.
    pub global: bool,
    /// Optional user filter supported by the summary endpoint.
    pub user_filter: Option<String>,
    /// Optional result limit.
    pub limit: Option<u32>,
}

impl SummaryQuery {
    pub(crate) fn pairs(&self) -> Result<Vec<(String, String)>, DataClientError> {
        if self.limit.is_some_and(|limit| limit == 0 || limit > 1000) {
            return Err(DataClientError::Query("summary limit must be 1..1000"));
        }
        let mut pairs = self.filters.pairs()?;
        if !self.group_by.is_empty() {
            pairs.push(("group_by".into(), self.group_by.join(",")));
        }
        if self.global {
            pairs.push(("scope".into(), "global".into()));
        }
        if let Some(value) = &self.user_filter {
            pairs.push(("user_filter".into(), value.clone()));
        }
        if let Some(limit) = self.limit {
            pairs.push(("limit".into(), limit.to_string()));
        }
        Ok(pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::{EventQuery, Filters, PageQuery, SummaryQuery};
    #[test]
    fn validates_time_ranges_and_page_budgets() {
        let instant = "2026-01-01T00:00:00Z".parse().expect("timestamp");
        let filters = Filters {
            from: Some(instant),
            to: Some(instant),
            ..Filters::default()
        };
        assert!(filters.pairs().is_err(), "empty time window rejected");
        assert!(
            PageQuery {
                page: 0,
                ..PageQuery::default()
            }
            .pairs()
            .is_err(),
            "one-based page"
        );
        assert!(
            PageQuery {
                page_size: 101,
                ..PageQuery::default()
            }
            .pairs()
            .is_err(),
            "bounded page size"
        );
        assert!(
            EventQuery {
                offset: u64::MAX,
                ..EventQuery::default()
            }
            .pairs()
            .is_err(),
            "offset fits backend signed integer"
        );
        assert!(
            SummaryQuery {
                limit: Some(0),
                ..SummaryQuery::default()
            }
            .pairs()
            .is_err(),
            "positive summary limit"
        );
    }
    #[test]
    fn preserves_repeated_exact_filters() {
        let filters = Filters {
            agents: vec!["a&b".into(), "中文".into()],
            ..Filters::default()
        };
        assert_eq!(
            filters.pairs().expect("valid filters"),
            vec![
                ("agent_name".into(), "a&b".into()),
                ("agent_name".into(), "中文".into())
            ],
            "serialization must not split values"
        );
    }
}
