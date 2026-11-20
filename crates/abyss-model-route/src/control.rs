//! Open user-supplied sources in the caller and submit their contents to the worker.

use crate::{
    CatalogRequest,
    cli::ControlCommand,
    read_request,
    rest::{self, Client},
    routing::{Load, Routes, Select},
    source,
    store::Store,
};
use hyper::Method;
use serde_json::Value;
use std::{io, path::Path};

pub fn request(
    client: &Client<'_>,
    legacy: Option<&Path>,
    command: ControlCommand,
) -> Result<(), String> {
    if let Some(path) = legacy.filter(|path| path.is_file()) {
        // Restore is create-only at the worker. Repeated imports after an interrupted
        // upgrade cannot overwrite an acknowledged selection or resurrect a cleared one.
        let saved = Store::read(path)?;
        client.request(Method::PUT, rest::PROFILE, encode(&saved)?)?;
        std::fs::remove_file(path).map_err(|_| "Cannot retire migrated routing profile.")?;
    }
    let value = match command {
        ControlCommand::Status => client.request(Method::GET, rest::STATUS, Vec::new())?,
        ControlCommand::State => client.request(Method::GET, rest::STATE, Vec::new())?,
        ControlCommand::Clear => client.request(Method::DELETE, rest::STATE, Vec::new())?,
        ControlCommand::Models => {
            let request = read_request()?;
            let profile = client.request(Method::GET, rest::PROFILE, Vec::new())?;
            let routes: Routes =
                serde_json::from_value(profile).map_err(|_| "Invalid route state.")?;
            let models = routes.list_models(&request)?;
            if request.include_metadata {
                serde_json::to_value(models)
            } else {
                serde_json::to_value(models.into_iter().map(|model| model.id).collect::<Vec<_>>())
            }
            .map_err(|_| "Cannot return models.")?
        }
        ControlCommand::Select => client.request(
            Method::PUT,
            rest::SELECTION,
            encode(&read_request::<Select>()?)?,
        )?,
        ControlCommand::Load => {
            let request: CatalogRequest = read_request()?;
            let load = Load {
                source: request.source.label()?.to_owned(),
                catalog: request.source.load(request.session.as_ref())?,
            };
            client.request(Method::PUT, rest::CATALOG, encode(&load)?)?
        }
        ControlCommand::File { name } => {
            let load = Load {
                source: source::json_file_name(&name)?.to_owned(),
                catalog: source::read_catalog(io::stdin().lock())?,
            };
            client.request(Method::PUT, rest::CATALOG, encode(&load)?)?
        }
    };
    output(&value)
}

fn encode(value: &impl serde::Serialize) -> Result<Vec<u8>, &'static str> {
    serde_json::to_vec(value).map_err(|_| "Cannot encode model route request.")
}

fn output(value: &Value) -> Result<(), String> {
    serde_json::to_writer(io::stdout().lock(), value)
        .map_err(|_| "Cannot return model routes.".into())
}
