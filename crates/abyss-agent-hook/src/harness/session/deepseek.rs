//! Session markers emitted by dsh's native and pi-ai LLM adapters.
//!
//! These conventions belong to the Harness, not to OpenAI or Anthropic APIs.
//! Callers must identify `DeepSeek` Harness before interpreting them.

use http::HeaderMap;
use serde_json::Value;

pub(super) struct DeepSeekSession;

impl DeepSeekSession {
    pub fn headers(headers: &HeaderMap) -> Option<String> {
        // Native dsh uses the first header; pi-ai uses session_id for OpenAI
        // affinity and x-session-id for OpenRouter affinity. Preserve the
        // generic session/thread headers ahead of cache-affinity fallbacks.
        [
            "x-deepseek-harness-session-id",
            "session-id",
            "thread-id",
            "session_id",
            "x-session-id",
        ]
        .into_iter()
        .find_map(|name| non_empty(headers.get(name)?.to_str().ok()?))
        .map(str::to_owned)
    }

    pub fn body(path: &str, body: &Value) -> Option<String> {
        let session_log = body.get("dsh_session_log");
        let log_session = session_log
            .filter(|log| log.get("version").and_then(Value::as_u64) == Some(1))
            .and_then(|log| log.pointer("/session/id"))
            .and_then(Value::as_str)
            .and_then(non_empty);
        log_session
            .or_else(|| {
                // dsh passes its session ID to pi-ai as the OpenAI cache key.
                // Other Harnesses may share cache keys across conversations.
                if !(path.ends_with("/responses") || path.ends_with("/chat/completions")) {
                    return None;
                }
                body.get("prompt_cache_key")
                    .and_then(Value::as_str)
                    .and_then(non_empty)
            })
            .map(str::to_owned)
    }
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

#[cfg(test)]
mod tests {
    use http::HeaderMap;
    use serde_json::json;

    use super::DeepSeekSession;

    #[test]
    fn native_session_header_takes_precedence_over_affinity() {
        let mut headers = HeaderMap::new();
        headers.insert("session_id", "affinity-session".parse().unwrap());
        headers.insert(
            "x-deepseek-harness-session-id",
            "  native-session  ".parse().unwrap(),
        );
        assert_eq!(
            DeepSeekSession::headers(&headers).as_deref(),
            Some("native-session")
        );
    }

    #[test]
    fn empty_headers_fall_through_but_request_and_user_ids_are_not_sessions() {
        let mut headers = HeaderMap::new();
        headers.insert("x-deepseek-harness-session-id", "  ".parse().unwrap());
        headers.insert("x-client-request-id", "request-1".parse().unwrap());
        headers.insert("x-deepseek-harness-user-id", "user-1".parse().unwrap());
        assert!(DeepSeekSession::headers(&headers).is_none());
        headers.insert("x-session-id", "session-1".parse().unwrap());
        assert_eq!(
            DeepSeekSession::headers(&headers).as_deref(),
            Some("session-1")
        );
    }

    #[test]
    fn session_log_requires_the_known_version_and_exact_session_path() {
        for body in [
            json!({"dsh_session_log": {"version": 2_u64, "session": {"id": "wrong-version"}}}),
            json!({"dsh_session_log": {"session": {"id": "unversioned"}}}),
            json!({"dsh_session_log": {"version": 1_u64, "session": {"id": 42_i32}}}),
            json!({"dsh_session_log": {"version": 1_u64, "session": {"id": " "}}}),
            json!({"messages": [{"content": {"dsh_session_log": {
                "version": 1_u64, "session": {"id": "user-content"}
            }}}]}),
        ] {
            assert!(DeepSeekSession::body("/anthropic/v1/messages", &body).is_none());
        }
        let body = json!({"dsh_session_log": {"version": 1_u64, "session": {"id": "session-1"}}});
        assert_eq!(
            DeepSeekSession::body("/anthropic/v1/messages", &body).as_deref(),
            Some("session-1")
        );
    }

    #[test]
    fn cache_key_is_a_fallback_on_openai_routes_only() {
        let body = json!({"prompt_cache_key": "cache-session"});
        for path in ["/v1/responses", "/gateway/chat/completions"] {
            assert_eq!(
                DeepSeekSession::body(path, &body).as_deref(),
                Some("cache-session")
            );
            for key in [json!(null), json!(42_i32), json!(" ")] {
                assert!(DeepSeekSession::body(path, &json!({"prompt_cache_key": key})).is_none());
            }
        }
        assert!(DeepSeekSession::body("/anthropic/v1/messages", &body).is_none());
        let body = json!({
            "prompt_cache_key": "cache-session",
            "dsh_session_log": {"version": 1_u64, "session": {"id": "native-session"}}
        });
        assert_eq!(
            DeepSeekSession::body("/responses", &body).as_deref(),
            Some("native-session")
        );
    }
}
