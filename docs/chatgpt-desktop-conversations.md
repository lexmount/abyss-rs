# ChatGPT desktop conversation turns

The desktop chat mode posts a messages envelope to the first-party conversation endpoint. The Codex mode uses the existing Responses protocol. Select the conversation dialect before generic inference on that exact HTTP operation and give the desktop conversation its ChatGPT harness identity. Preserve configured harness content and enablement settings.

Implement the dialect in the OpenAI protocol family using ProtocolParser and the shared HTTP request/response composition. Each message stream slot has its own document. Consecutive v1 delta envelopes inherit the preceding channel, path and operation. Apply batched operations in sequence, keeping visible user and assistant text and excluding hidden copies, tools and reasoning. Use the provider conversation ID from the first response or the continuation request, the visible reply ID and the request parent to correlate turns. The existing normalizer, delivery protocol and session UI own all downstream behavior.

Replay two captured turns through a local broker and private standalone backend, then open the session in the dashboard. Synthetic fixtures cover interleaved streams, control inspection, truncation and Codex isolation. Ship a development macOS installer using the standard broker build.
