//! Command dispatch and bounded pagination with resumable continuation metadata.

use crate::{
    args::{Cli, Command, EventArgs, EventCommand, PageArgs, SessionCommand, UsageCommand},
    config::ConfigFile,
    credentials::CredentialResolver,
    error::QueryError as Error,
    output::Output,
};
use abyss_data_client::{ApiEndpoint, DataClient, query::PageQuery};
use serde_json::{Value, json};

pub fn execute(cli: &Cli) -> Result<Output, Error> {
    if matches!(cli.command, Command::Schema) {
        return Ok(Output::schema());
    }
    let config_file = ConfigFile::new(cli.config.as_deref())?;
    if let Command::Profile { command } = &cli.command {
        return Ok(Output::new(
            "profile",
            config_file.command(command, cli.profile.as_deref())?,
        ));
    }
    let config = config_file.read()?;
    let (name, profile) = config.selected(cli.profile.as_deref())?;
    if let Command::Auth { command } = &cli.command {
        return Ok(Output::new(
            "auth",
            crate::auth::execute(command, &config_file, name, profile)?,
        ));
    }
    let client = DataClient::new(
        ApiEndpoint::parse_with_http(&profile.endpoint, profile.allow_http)?,
        CredentialResolver::resolve(&config_file, name, profile)?,
        &profile.options()?,
    )?;
    match &cli.command {
        Command::Doctor => {
            client.sessions(&PageQuery {
                page_size: 1_u32,
                ..PageQuery::default()
            })?;
            Ok(Output::new(
                "doctor",
                json!({"ok":true,"profile":name,"session_read":true}),
            ))
        }
        Command::Search { query, page } => SessionPages::new(&client).fetch(page, Some(query)),
        Command::Sessions { command } => match command {
            SessionCommand::List(page) => SessionPages::new(&client).fetch(page, None),
            SessionCommand::Get { id } => Ok(Output::new(
                "sessions.get",
                serde_json::to_value(client.session(*id)?)?,
            )),
            SessionCommand::Outline { id } => Ok(Output::new(
                "sessions.outline",
                serde_json::to_value(client.outline(*id)?)?,
            )),
            SessionCommand::Trajectory { id } => Ok(Output::new(
                "sessions.trajectory",
                serde_json::to_value(client.trajectory(*id)?)?,
            )),
        },
        Command::Events { command } => match command {
            EventCommand::List(args) => EventPages::new(&client).fetch(args),
            EventCommand::Get { id } => Ok(Output::new(
                "events.get",
                serde_json::to_value(client.event(*id)?)?,
            )),
        },
        Command::Usage {
            command: UsageCommand::Summary(args),
        } => Ok(Output::new(
            "usage.summary",
            serde_json::to_value(client.summary(&args.query())?)?,
        )),
        Command::Profile { .. } | Command::Auth { .. } | Command::Schema => {
            unreachable!("local commands returned before constructing the data client")
        }
    }
}

struct SessionPages<'a> {
    client: &'a DataClient,
}
impl<'a> SessionPages<'a> {
    const fn new(client: &'a DataClient) -> Self {
        Self { client }
    }
    fn fetch(&self, args: &PageArgs, search: Option<&str>) -> Result<Output, Error> {
        let mut query = args.query();
        // Keep page_size constant: changing it between pages changes the offset.
        query.page_size = query.page_size.min(args.paging.max_items);
        let mut items = Vec::new();
        let mut pages = 0_u32;
        let mut budget = crate::budget::OutputBudget::new();
        loop {
            let mut value = if let Some(text) = search {
                serde_json::to_value(self.client.search(text, &query)?)?
            } else {
                serde_json::to_value(self.client.sessions(&query)?)?
            };
            budget.include(&value)?;
            let batch = value
                .get_mut("items")
                .and_then(Value::as_array_mut)
                .ok_or(Error::Protocol("missing session items"))?;
            let count = u32::try_from(batch.len())
                .map_err(|_| Error::Protocol("oversized session page"))?;
            if count > query.page_size {
                return Err(Error::Protocol(
                    "server exceeded requested session page size",
                ));
            }
            items.append(batch);
            let page = value.get("page").and_then(Value::as_u64);
            let size = value.get("page_size").and_then(Value::as_u64);
            if page != Some(u64::from(query.page)) || size != Some(u64::from(query.page_size)) {
                return Err(Error::Protocol(
                    "server returned a different pagination window",
                ));
            }
            let more = value
                .get("has_more")
                .and_then(Value::as_bool)
                .ok_or(Error::Protocol("missing has_more"))?;
            if more && count == 0 {
                return Err(Error::Protocol("empty session page has a continuation"));
            }
            pages = pages.saturating_add(1);
            let next_page = if more {
                query
                    .page
                    .checked_add(1)
                    .ok_or(Error::Protocol("page overflow"))?
            } else {
                query.page
            };
            let next = if more {
                json!({"page":next_page,"page_size":query.page_size})
            } else {
                Value::Null
            };
            let remaining = usize::try_from(args.paging.max_items)
                .unwrap_or(usize::MAX)
                .saturating_sub(items.len());
            // Stop before a page that could exceed the item budget; metadata lets
            // callers resume the exact window without dropping or duplicating rows.
            let bounded = remaining < usize::try_from(query.page_size).unwrap_or(usize::MAX)
                || pages >= args.paging.max_pages;
            if !more || !args.paging.all || bounded {
                value
                    .as_object_mut()
                    .ok_or(Error::Protocol("invalid page"))?
                    .remove("items");
                return Ok(Output::paginated(
                    if search.is_some() {
                        "search"
                    } else {
                        "sessions.list"
                    },
                    items,
                    pages,
                    &next,
                    more && args.paging.all && bounded,
                    &value,
                ));
            }
            query.page = next_page;
        }
    }
}

struct EventPages<'a> {
    client: &'a DataClient,
}
impl<'a> EventPages<'a> {
    const fn new(client: &'a DataClient) -> Self {
        Self { client }
    }
    fn fetch(&self, args: &EventArgs) -> Result<Output, Error> {
        let mut query = args.query();
        let mut items = Vec::new();
        let mut pages = 0_u32;
        let mut budget = crate::budget::OutputBudget::new();
        loop {
            let remaining = args
                .paging
                .max_items
                .saturating_sub(u32::try_from(items.len()).unwrap_or(u32::MAX));
            query.limit = args.limit.min(remaining);
            let page = self.client.events(&query)?;
            budget.include(&page)?;
            if page.events.len() > usize::try_from(query.limit).unwrap_or(usize::MAX) {
                return Err(Error::Protocol("server exceeded requested event limit"));
            }
            let next_offset = page
                .next_page_token
                .as_ref()
                .map(|token| {
                    token
                        .parse::<u64>()
                        .ok()
                        .filter(|offset| {
                            *offset > query.offset && *offset <= i64::MAX.unsigned_abs()
                        })
                        .ok_or(Error::Protocol(
                            "invalid or non-advancing event continuation",
                        ))
                })
                .transpose()?;
            if next_offset.is_some() && page.events.is_empty() {
                return Err(Error::Protocol("empty event page has a continuation"));
            }
            for event in page.events {
                items.push(serde_json::to_value(event)?);
            }
            pages = pages.saturating_add(1);
            let bounded = items.len()
                >= usize::try_from(args.paging.max_items).unwrap_or(usize::MAX)
                || pages >= args.paging.max_pages;
            if next_offset.is_none() || !args.paging.all || bounded {
                let next = next_offset.map_or(Value::Null, |offset| json!({"offset":offset}));
                return Ok(Output::paginated(
                    "events.list",
                    items,
                    pages,
                    &next,
                    next_offset.is_some() && args.paging.all && bounded,
                    &serde_json::to_value(page.fields)?,
                ));
            }
            query.offset = next_offset.ok_or(Error::Protocol("missing continuation"))?;
        }
    }
}
