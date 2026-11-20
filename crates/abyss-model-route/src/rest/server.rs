//! Decode bounded management requests and commit them for the connected OS principal.

use bytes::Bytes;
use http_body_util::{BodyExt as _, Full, Limited};
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, server::conn::http1, service::service_fn,
};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{convert::Infallible, sync::Arc, time::Duration};

use crate::{
    store::{Change, Store},
    sys,
};

type Reply = Response<Full<Bytes>>;

pub async fn serve(mut listener: sys::Listener, store: Arc<Store>) -> Result<(), &'static str> {
    let slots = Arc::new(tokio::sync::Semaphore::new(32));
    loop {
        let permit = Arc::clone(&slots)
            .acquire_owned()
            .await
            .map_err(|_| "Control service stopped.")?;
        let stream = listener
            .accept()
            .await
            .map_err(|_| "Cannot accept local route control.")?;
        let Ok(peer) = sys::peer(&stream) else {
            continue;
        };
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let _permit = permit;
            let service = service_fn(|request| handle(request, &peer, Arc::clone(&store)));
            let connection = http1::Builder::new()
                .keep_alive(false)
                .serve_connection(TokioIo::new(stream), service);
            let _result = tokio::time::timeout(Duration::from_secs(15), connection).await;
        });
    }
}

async fn handle(
    request: Request<Incoming>,
    peer: &sys::Peer,
    store: Arc<Store>,
) -> Result<Reply, Infallible> {
    let reply = match sys::principal(peer) {
        Err(_) => response(
            StatusCode::FORBIDDEN,
            &json!({"error":"Cannot identify route owner."}),
        ),
        Ok(owner) => {
            let (parts, body) = request.into_parts();
            match Limited::new(body, usize::try_from(super::LIMIT).unwrap_or(usize::MAX))
                .collect()
                .await
            {
                Ok(body) => {
                    // File commits and catalog parsing cannot stall the inspection scheduler.
                    let result = tokio::task::spawn_blocking(move || {
                        dispatch(
                            &parts.method,
                            parts.uri.path(),
                            &body.to_bytes(),
                            &owner,
                            &store,
                        )
                    })
                    .await;
                    match result {
                        Ok(Ok(value)) => response(StatusCode::OK, &value),
                        Ok(Err((status, message))) => response(status, &json!({"error":message})),
                        Err(_) => response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &json!({"error":"Route management interrupted."}),
                        ),
                    }
                }
                Err(_) => response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    &json!({"error":"Invalid request body or size."}),
                ),
            }
        }
    };
    Ok(reply)
}

fn dispatch(
    method: &Method,
    path: &str,
    body: &[u8],
    owner: &str,
    store: &Store,
) -> Result<Value, (StatusCode, &'static str)> {
    let bad = |message| (StatusCode::BAD_REQUEST, message);
    let change = match (method, path) {
        (&Method::GET, super::STATUS) => return Ok(json!({"broker_pid": store.broker_pid})),
        (&Method::GET, super::STATE) => {
            return store
                .get(owner)
                .as_deref()
                .map_or_else(
                    || crate::routing::Routes::default().snapshot(),
                    crate::routing::Routes::snapshot,
                )
                .map_err(bad);
        }
        (&Method::POST, super::MODELS) => {
            let request: crate::catalog::ModelListRequest =
                serde_json::from_slice(body).map_err(|_| bad("Invalid model list request."))?;
            let routes = store
                .get(owner)
                .ok_or_else(|| bad("No model catalog configured."))?;
            let models = routes.list_models(&request).map_err(bad)?;
            return if request.include_metadata {
                serde_json::to_value(models)
            } else {
                serde_json::to_value(models.into_iter().map(|model| model.id).collect::<Vec<_>>())
            }
            .map_err(|_| bad("Cannot encode model list."));
        }
        (&Method::PUT, super::PROFILE) => Change::Restore(
            serde_json::from_slice(body).map_err(|_| bad("Invalid saved profile."))?,
        ),
        (&Method::PUT, super::CATALOG) => {
            Change::Import(serde_json::from_slice(body).map_err(|_| bad("Invalid model catalog."))?)
        }
        (&Method::PUT, super::SELECTION) => {
            Change::Select(serde_json::from_slice(body).map_err(|_| bad("Invalid selection."))?)
        }
        (&Method::DELETE, super::STATE) => Change::Clear,
        _ => return Err((StatusCode::NOT_FOUND, "Unknown route resource.")),
    };
    store.update(owner, change).map_err(bad)
}

fn response(status: StatusCode, value: &Value) -> Reply {
    let mut reply = Response::new(Full::new(Bytes::from(value.to_string())));
    *reply.status_mut() = status;
    reply.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    reply.headers_mut().insert(
        "cache-control",
        hyper::header::HeaderValue::from_static("no-store"),
    );
    reply
}
