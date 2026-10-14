//! Harness-owned session conventions, applied only after unambiguous identification.

mod deepseek;

use abyss_mitm::HttpExchange;
use http::HeaderMap;

use super::{BuiltInHarness, HarnessId};
use deepseek::DeepSeekSession;

pub(super) struct HarnessSessionResolver;

impl HarnessSessionResolver {
    pub fn http(harness_id: &HarnessId, exchange: &HttpExchange) -> Option<String> {
        if harness_id.as_str() != BuiltInHarness::DeepSeekHarness.id() {
            return None;
        }
        DeepSeekSession::headers(exchange.request.headers()).or_else(|| {
            DeepSeekSession::body(
                exchange.request.uri().path(),
                exchange.request.body().json()?,
            )
        })
    }

    pub fn headers(harness_id: &HarnessId, headers: &HeaderMap) -> Option<String> {
        if harness_id.as_str() != BuiltInHarness::DeepSeekHarness.id() {
            return None;
        }
        DeepSeekSession::headers(headers)
    }
}
