# Claude Desktop Code sessions

Claude Desktop subscribes to cloud Code sessions through `GET /v1/code/sessions/{id}/events/stream` on `claude.ai`. The long-lived SSE response can carry several model calls. Abyss emits usage as each call completes, while the same HTTP exchange is still open.

The usage hook opts in through `observe_http_response`. Its `HttpResponseObserver` receives content-decoded bytes while the relay forwards the original response. The observer owns the SSE and call state for that response and drops unfinished calls when observation ends. It is the sole source of usage events for this route.

The Claude Code session dialect groups stream events by `api_message_id` from `message_start` to `message_stop`. It uses observed user messages since the previous completed call as request context and reads usage from the call's own message events. It takes the session ID from the subscription path, maps `cse_` to `session_`, and uses the standard Harness registry for client attribution. A call takes its response time from the relay block completing `message_stop` and estimates its request time as the relay time of the block completing `message_start` minus `ttft_ms`, using the response time when `ttft_ms` is absent.
