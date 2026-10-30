//! Command grammar; query execution never initiates an interactive login.

use std::path::PathBuf;

use abyss_data_client::query::{
    EventFields, EventQuery, EventSide, Filters, PageQuery, PreviewQuery, SummaryQuery,
};
use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "abyss-query",
    version,
    about = "Read Abyss backend data from an Agent or terminal"
)]
pub struct Cli {
    #[arg(long, global = true, env = "ABYSS_QUERY_CONFIG")]
    pub config: Option<PathBuf>,
    #[arg(long, global = true, env = "ABYSS_QUERY_PROFILE")]
    pub profile: Option<String>,
    #[arg(long, global = true, value_enum, default_value = "json")]
    pub format: Format,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Format {
    Json,
    Jsonl,
    Table,
}

#[derive(Subcommand)]
pub enum Command {
    /// Manage named endpoints and their authentication policy.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
    /// Explicit terminal login, local credential status, or remote logout.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Verify configuration, credentials and actual session-read permission.
    Doctor,
    /// Search session content through the backend's search index.
    Search {
        query: String,
        #[command(flatten)]
        page: PageArgs,
    },
    Sessions {
        #[command(subcommand)]
        command: SessionCommand,
    },
    Events {
        #[command(subcommand)]
        command: EventCommand,
    },
    Usage {
        #[command(subcommand)]
        command: UsageCommand,
    },
    /// Print versioned output and backend DTO JSON Schemas, without connecting.
    Schema,
}

#[derive(Subcommand)]
pub enum ProfileCommand {
    Add(ProfileAdd),
    List,
    Show { name: Option<String> },
    Use { name: String },
    Remove { name: String },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum AuthMode {
    None,
    Bearer,
    Terminal,
}

#[derive(Clone, Copy, Default, ValueEnum, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStore {
    #[default]
    Keyring,
    File,
}

#[derive(Args)]
pub struct ProfileAdd {
    pub name: String,
    /// API root; include /api/ when required by the deployment.
    #[arg(long)]
    pub endpoint: String,
    /// Explicitly permit unencrypted HTTP to non-loopback deployments.
    #[arg(long)]
    pub allow_http: bool,
    #[arg(long, value_enum)]
    pub auth: AuthMode,
    /// Name of an environment variable containing the raw bearer token.
    #[arg(long, conflicts_with_all = ["token_file", "header_file"])]
    pub token_env: Option<String>,
    #[arg(long, conflicts_with = "header_file")]
    pub token_file: Option<PathBuf>,
    /// File containing exactly one Authorization: Bearer ... header.
    #[arg(long)]
    pub header_file: Option<PathBuf>,
    /// Control-plane root for terminal PKCE login; independent of data endpoint.
    #[arg(long)]
    pub auth_endpoint: Option<String>,
    /// File persistence is available on Unix; other platforms use the OS keyring.
    #[arg(long, value_enum, default_value = "keyring")]
    pub credential_store: CredentialStore,
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=600))]
    pub timeout: u64,
    #[arg(long, default_value_t = 8_388_608)]
    pub max_response_bytes: usize,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u8).range(0..=3))]
    pub retries: u8,
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Print a verification URL to stderr and wait for browser authorization.
    Login {
        #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..=600))]
        timeout: u64,
    },
    /// Inspect local availability and expiry, without displaying the credential.
    Status,
    /// Revoke the terminal session before deleting its local credential.
    Logout {
        /// Delete locally even when remote revocation cannot be reached.
        #[arg(long)]
        local_only: bool,
    },
}

#[derive(Args, Clone, Default)]
pub struct FilterArgs {
    #[arg(long)]
    pub from: Option<DateTime<Utc>>,
    #[arg(long)]
    pub to: Option<DateTime<Utc>>,
    #[arg(long = "agent")]
    pub agents: Vec<String>,
    #[arg(long = "provider")]
    pub providers: Vec<String>,
    #[arg(long = "model")]
    pub models: Vec<String>,
}
impl FilterArgs {
    pub fn query(&self) -> Filters {
        Filters {
            from: self.from,
            to: self.to,
            agents: self.agents.clone(),
            providers: self.providers.clone(),
            models: self.models.clone(),
        }
    }
}

#[derive(Args)]
pub struct Paging {
    /// Follow continuation tokens, subject to --max-items and --max-pages.
    #[arg(long)]
    pub all: bool,
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    pub max_items: u32,
    #[arg(long, default_value_t = 100, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub max_pages: u32,
}

#[derive(Args)]
pub struct PageArgs {
    #[command(flatten)]
    pub filters: FilterArgs,
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub page: u32,
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=100))]
    pub page_size: u32,
    #[command(flatten)]
    pub paging: Paging,
}
impl PageArgs {
    pub fn query(&self) -> PageQuery {
        PageQuery {
            filters: self.filters.query(),
            page: self.page,
            page_size: self.page_size,
        }
    }
}

#[derive(Subcommand)]
pub enum SessionCommand {
    List(PageArgs),
    /// Session timeline (`SaaS` data service).
    Get {
        id: Uuid,
    },
    /// Content-free session outline (`SaaS` data service).
    Outline {
        id: Uuid,
    },
    /// Normalized session trajectory (`SaaS` data service).
    Trajectory {
        id: Uuid,
    },
    /// Session page header (standalone backend).
    Header {
        id: Uuid,
    },
    /// Session segments (standalone backend).
    Streams {
        id: Uuid,
    },
    /// Session turn tree (standalone backend).
    Turns {
        id: Uuid,
    },
    /// One segment's exchanges (standalone backend).
    Segment {
        id: Uuid,
        head: String,
        #[command(flatten)]
        preview: PreviewArgs,
    },
    /// Literal search inside one session (standalone backend).
    Search {
        id: Uuid,
        query: String,
    },
}
#[derive(Subcommand)]
pub enum EventCommand {
    List(EventArgs),
    Get {
        id: Uuid,
    },
    /// Preview of an event's conversation entries (standalone backend).
    Conversation {
        id: Uuid,
        #[command(flatten)]
        preview: PreviewArgs,
    },
    /// An event's place in its session (standalone backend).
    Location {
        id: Uuid,
    },
}
#[derive(Args)]
pub struct PreviewArgs {
    /// Comma-separated entry runs: `a-b`, `-n` (last n) or `a`; write `--entries=-n`.
    #[arg(long)]
    pub entries: Option<String>,
    /// Most UTF-16 code units kept of each entry text.
    #[arg(long)]
    pub text_preview: Option<u32>,
}
impl PreviewArgs {
    pub fn query(&self) -> PreviewQuery {
        PreviewQuery {
            entries: self.entries.clone(),
            text_preview: self.text_preview,
        }
    }
}
#[derive(Clone, Copy, ValueEnum)]
pub enum Side {
    Request,
    Response,
}
impl Side {
    const fn query(self) -> EventSide {
        match self {
            Self::Request => EventSide::Request,
            Self::Response => EventSide::Response,
        }
    }
}
#[derive(Args)]
pub struct EventArgs {
    #[command(flatten)]
    pub filters: FilterArgs,
    #[arg(long = "session-id")]
    pub session_ids: Vec<String>,
    #[arg(long)]
    pub session_pk: Option<Uuid>,
    /// Normalized turn number (`SaaS` data service).
    #[arg(long)]
    pub turn_index: Option<i32>,
    #[arg(long, value_enum)]
    pub event_type: Option<Side>,
    #[arg(long)]
    pub full: bool,
    /// Add each event's current location (standalone backend).
    #[arg(long)]
    pub locate: bool,
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub limit: u32,
    #[arg(long, default_value_t = 0)]
    pub offset: u64,
    #[command(flatten)]
    pub paging: Paging,
}
impl EventArgs {
    pub fn query(&self) -> EventQuery {
        EventQuery {
            filters: self.filters.query(),
            session_ids: self.session_ids.clone(),
            session_pk: self.session_pk,
            turn_index: self.turn_index,
            side: self.event_type.map(Side::query),
            fields: if self.full {
                EventFields::Full
            } else {
                EventFields::List
            },
            locate: self.locate,
            limit: self.limit,
            offset: self.offset,
        }
    }
}
#[derive(Subcommand)]
pub enum UsageCommand {
    Summary(SummaryArgs),
}
#[derive(Args)]
pub struct SummaryArgs {
    #[command(flatten)]
    pub filters: FilterArgs,
    #[arg(long, value_delimiter = ',')]
    pub group_by: Vec<String>,
    /// Aggregate across users (`SaaS` data service, administrators only).
    #[arg(long)]
    pub global: bool,
    #[arg(long)]
    pub user_filter: Option<String>,
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=1000))]
    pub limit: Option<u32>,
}
impl SummaryArgs {
    pub fn query(&self) -> SummaryQuery {
        SummaryQuery {
            filters: self.filters.query(),
            group_by: self.group_by.clone(),
            global: self.global,
            user_filter: self.user_filter.clone(),
            limit: self.limit,
        }
    }
}
