#!/usr/bin/env bash

# Shared assertions for provider black-box tests. These helpers keep the
# provider scripts focused on starting services and issuing native requests.

blackbox_extract_codex_usage() {
  local jsonl_file="$1"

  jq -c -e -s '
    ([.[] | select((.type == "turn.failed") or (.type == "error"))]) as $failures
    | ([.[] | select(.type == "turn.completed")]) as $completed
    | if ($failures | length) > 0 then
        error("Codex emitted a failed or error event")
      elif ($completed | length) != 1 then
        error("expected exactly one Codex turn.completed event")
      else
        $completed[0].usage as $usage
        | if ($usage | type) != "object" then
            error("Codex turn.completed event has no usage object")
          elif ($usage.input_tokens | type) != "number"
            or ($usage.output_tokens | type) != "number"
            or (($usage.cached_input_tokens // 0) | type) != "number"
            or (($usage.cache_write_input_tokens // 0) | type) != "number"
            or (($usage.reasoning_output_tokens // 0) | type) != "number" then
            error("Codex usage schema has an invalid token field")
          else
            {
              input_tokens: $usage.input_tokens,
              cached_input_tokens: ($usage.cached_input_tokens // 0),
              cache_write_input_tokens: ($usage.cache_write_input_tokens // 0),
              output_tokens: $usage.output_tokens,
              reasoning_output_tokens: ($usage.reasoning_output_tokens // 0)
            }
          end
      end
  ' "${jsonl_file}"
}

blackbox_extract_event_pair() {
  local events_file="$1"
  local marker="$2"
  local agent_name="$3"
  local provider="$4"

  jq -c \
    --arg marker "${marker}" \
    --arg agent_name "${agent_name}" \
    --arg provider "${provider}" \
    '
      .events as $events
      | [$events[]
          | select(
              .event_type == "request"
              and .agent_name == $agent_name
              and .llm_provider == $provider
              and (.text | type == "string" and contains($marker))
            )] as $requests
      | if ($requests | length) == 0 then
          empty
        elif ($requests | length) != 1 then
          error("expected exactly one marker request event")
        else
          $requests[0] as $request
          | [$events[]
              | select(
                  .event_type == "response"
                  and .agent_name == $agent_name
                  and .llm_provider == $provider
                  and .session_id == $request.session_id
                  and .turn_index == $request.turn_index
                )] as $responses
          | if ($responses | length) == 0 then
              empty
            elif ($responses | length) != 1 then
              error("expected exactly one response for marker request")
            else
              {request: $request, response: $responses[0]}
            end
        end
    ' "${events_file}"
}

blackbox_assert_pair_identity() {
  local pair_json="$1"

  jq -e '
    .request.event_type == "request"
    and .response.event_type == "response"
    and (.request.event_id | type == "string" and length > 0)
    and (.response.event_id | type == "string" and length > 0)
    and .request.event_id != .response.event_id
    and (.request.session_id | type == "string" and length > 0)
    and .request.session_id == .response.session_id
    and (.request.turn_index | type == "number")
    and .request.turn_index == .response.turn_index
  ' <<<"${pair_json}" >/dev/null
}

blackbox_assert_codex_usage_matches_pair() {
  local usage_json="$1"
  local pair_json="$2"

  jq -e \
    --argjson usage "${usage_json}" \
    --argjson pair "${pair_json}" \
    '
      $usage.input_tokens == $pair.request.input_tokens
      and $usage.cached_input_tokens == $pair.request.cache_read_tokens
      and $usage.cache_write_input_tokens == $pair.request.cache_write_tokens
      and $usage.output_tokens == $pair.response.output_tokens
      and $usage.reasoning_output_tokens == $pair.response.reasoning_tokens
    ' <<<"{}" >/dev/null
}

blackbox_assert_summary_matches_pair() {
  local summary_json="$1"
  local pair_json="$2"
  local pairs_json

  pairs_json="$(jq -cn --argjson pair "${pair_json}" '[ $pair ]')"
  blackbox_assert_summary_matches_pairs "${summary_json}" "${pairs_json}"
}

blackbox_assert_summary_matches_pairs() {
  local summary_json="$1"
  local pairs_json="$2"

  jq -e \
    --argjson pairs "${pairs_json}" \
    '
      (.rows // []) as $rows
      | if ($rows | length) == 0 or ($pairs | length) == 0 then
          error("usage summary has no rows")
        else
          (reduce $rows[] as $row
            ({requests: 0, responses: 0, input_tokens: 0, output_tokens: 0,
              cache_read_tokens: 0, cache_write_tokens: 0, reasoning_tokens: 0,
              total_tokens: 0};
              .requests += ($row.requests // 0)
              | .responses += ($row.responses // 0)
              | .input_tokens += ($row.input_tokens // 0)
              | .output_tokens += ($row.output_tokens // 0)
              | .cache_read_tokens += ($row.cache_read_tokens // 0)
              | .cache_write_tokens += ($row.cache_write_tokens // 0)
              | .reasoning_tokens += ($row.reasoning_tokens // 0)
              | .total_tokens += ($row.total_tokens // 0)
            )) as $actual
          | (reduce $pairs[] as $pair
            ({requests: 0, responses: 0, input_tokens: 0, output_tokens: 0,
              cache_read_tokens: 0, cache_write_tokens: 0, reasoning_tokens: 0,
              total_tokens: 0};
              .requests += 1
              | .responses += 1
              | .input_tokens += $pair.request.input_tokens
              | .output_tokens += $pair.response.output_tokens
              | .cache_read_tokens
                += ($pair.request.cache_read_tokens + $pair.response.cache_read_tokens)
              | .cache_write_tokens
                += ($pair.request.cache_write_tokens + $pair.response.cache_write_tokens)
              | .reasoning_tokens += $pair.response.reasoning_tokens
              | .total_tokens += ($pair.request.total_tokens + $pair.response.total_tokens)
            )) as $expected
          | if (
              $actual.requests == $expected.requests
              and $actual.responses == $expected.responses
              and $actual.input_tokens == $expected.input_tokens
              and $actual.output_tokens == $expected.output_tokens
              and $actual.cache_read_tokens == $expected.cache_read_tokens
              and $actual.cache_write_tokens == $expected.cache_write_tokens
              and $actual.reasoning_tokens == $expected.reasoning_tokens
              and $actual.total_tokens == $expected.total_tokens
            ) then
              true
            else
              error(({
                message: "usage summary does not match expected event pairs",
                actual: $actual,
                expected: $expected
              } | tojson))
            end
        end
    ' <<<"${summary_json}" >/dev/null
}

blackbox_fetch_summary() {
  local base_url="$1"
  local native_token="$2"
  local agent_name="$3"
  local provider="$4"
  local session_id="$5"
  local curl_timeout_seconds="$6"

  curl -fsS \
    --max-time "${curl_timeout_seconds}" \
    -H "Authorization: Bearer ${native_token}" \
    --get "${base_url}/v1/agent-usage/summary" \
    --data-urlencode "scope=mine" \
    --data-urlencode "group_by=event_type" \
    --data-urlencode "fields=full" \
    --data-urlencode "agent_name=${agent_name}" \
    --data-urlencode "llm_provider=${provider}" \
    --data-urlencode "session_id=${session_id}"
}
