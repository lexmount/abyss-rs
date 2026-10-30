//! Versioned machine output and terminal-safe human rendering.

use crate::{args::Format, error::QueryError as Error};
use schemars::JsonSchema;
use serde::Serialize;
use serde_json::{Value, json};
use std::io::{self, Write as _};

#[derive(Serialize, JsonSchema)]
pub struct Output {
    schema_version: u32,
    command: String,
    data: Value,
    meta: Value,
}
impl Output {
    pub fn new(command: &str, data: Value) -> Self {
        Self {
            schema_version: 1_u32,
            command: command.into(),
            data,
            meta: json!({}),
        }
    }
    pub fn paginated(
        command: &str,
        items: Vec<Value>,
        pages: u32,
        next: &Value,
        truncated: bool,
        backend: &Value,
    ) -> Self {
        Self {
            schema_version: 1_u32,
            command: command.into(),
            data: Value::Array(items),
            meta: json!({"pages":pages,"next":next,"truncated":truncated,"backend":backend}),
        }
    }
    pub fn write(&self, format: Format) -> Result<(), Error> {
        let mut stdout = io::stdout().lock();
        match format {
            Format::Json => {
                writeln!(stdout, "{}", serde_json::to_string(self)?)?;
            }
            Format::Jsonl => {
                let records = self
                    .data
                    .as_array()
                    .map_or_else(|| std::slice::from_ref(&self.data), Vec::as_slice);
                for record in records {
                    writeln!(
                        stdout,
                        "{}",
                        json!({"schema_version":1_u32,"command":self.command,"record":record})
                    )?;
                }
                writeln!(
                    stdout,
                    "{}",
                    json!({"schema_version":1_u32,"command":self.command,"meta":self.meta})
                )?;
            }
            Format::Table => {
                writeln!(stdout, "ID\tAGENT\tDATA (JSON)")?;
                let records = self
                    .data
                    .as_array()
                    .map_or_else(|| std::slice::from_ref(&self.data), Vec::as_slice);
                for record in records {
                    let id = record
                        .get("session_pk")
                        .or_else(|| record.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or("-");
                    let agent = record
                        .get("agent_name")
                        .and_then(Value::as_str)
                        .unwrap_or("-");
                    // JSON escaping also prevents terminal control sequences from data.
                    writeln!(stdout, "{}\t{}\t{record}", json!(id), json!(agent))?;
                }
                writeln!(stdout, "meta\t{}", self.meta)?;
            }
        }
        stdout.flush()?;
        Ok(())
    }
    pub fn schema() -> Self {
        use abyss_data_client::models::{
            ConversationPreview, EventLocation, EventPage, SearchPage, Segment, SessionHeader,
            SessionPage, SessionSearch, SessionStreams, SessionTimeline, SessionTrajectory,
            SessionTurns, UsageEvent, UsageSummary,
        };
        Self::new(
            "schema",
            json!({
                "envelope":schemars::schema_for!(Self),
                "session_page":schemars::schema_for!(SessionPage),"search_page":schemars::schema_for!(SearchPage),
                "session_timeline":schemars::schema_for!(SessionTimeline),"session_trajectory":schemars::schema_for!(SessionTrajectory),
                "session_header":schemars::schema_for!(SessionHeader),"session_streams":schemars::schema_for!(SessionStreams),
                "session_turns":schemars::schema_for!(SessionTurns),"segment":schemars::schema_for!(Segment),
                "session_search":schemars::schema_for!(SessionSearch),
                "event_page":schemars::schema_for!(EventPage),"event":schemars::schema_for!(UsageEvent),
                "conversation_preview":schemars::schema_for!(ConversationPreview),"event_location":schemars::schema_for!(EventLocation),
                "summary":schemars::schema_for!(UsageSummary)
            }),
        )
    }
}
