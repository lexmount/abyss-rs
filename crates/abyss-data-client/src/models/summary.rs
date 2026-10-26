//! Usage aggregation response without assumptions about grouping dimensions.

use super::Extensions;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One backend aggregation result. Rows retain nullable/estimated usage metadata.
#[derive(Deserialize, Serialize, JsonSchema)]
pub struct UsageSummary {
    /// Grouping dimensions actually applied.
    pub group_by: Vec<String>,
    /// Aggregation rows, whose fields depend on the requested dimensions.
    pub rows: Vec<serde_json::Value>,
    /// Reserved backend pagination field; currently summaries are single-page.
    pub next_page_token: Option<String>,
    /// Echoed time bounds and additional metadata.
    #[serde(flatten)]
    pub fields: Extensions,
}
