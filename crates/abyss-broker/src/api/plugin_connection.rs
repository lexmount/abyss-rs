//! Authenticated management-API upgrade into the existing plugin session protocol.
use axum::{
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse as _, Response},
};

use super::AppState;

/// The parent router applies the same bearer authorization as policy updates.
pub(super) async fn connect(State(state): State<AppState>, mut request: Request) -> Response {
    let headers = request.headers();
    if headers
        .get(header::UPGRADE)
        .and_then(|value| value.to_str().ok())
        != Some("abyss-plugin-v1")
        || !headers
            .get(header::CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|part| part.trim().eq_ignore_ascii_case("upgrade"))
            })
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        if let Ok(stream) = upgrade.await {
            let _attached = state
                .plugins
                .attach(hyper_util::rt::TokioIo::new(stream))
                .await;
        }
    });
    (
        StatusCode::SWITCHING_PROTOCOLS,
        [
            (header::CONNECTION, "upgrade"),
            (header::UPGRADE, "abyss-plugin-v1"),
        ],
    )
        .into_response()
}
