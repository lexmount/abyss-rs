# MiniMax compatible protocol fixtures

These are synthetic, credential-free contract examples, not production captures.
They use `MiniMax-M3.1-Flash` and the public Messages, Chat Completions, and
Responses shapes linked in [the integration guide](../../../../../docs/minimax.md).

Each JSON file contains a request, its tool-call response, the following request
with the tool result and preserved thinking history, and the final answer. The
SSE file represents the first response. Counts are intentionally small:
40 uncached input + 60 cached input + 12 output = 112 total tokens; 5 reasoning
tokens are included in output. The followup has 60 uncached input tokens.

Responses places full reasoning in `content` while `summary` is empty. Messages
reports uncached input separately and uses `output_tokens_details.thinking_tokens`.
Chat Completions separates `reasoning_content` and includes an argument-only
delta with an empty ID, which must not erase the preceding tool identity.
