# Model provider selection at the request boundary

Model clients can use a different HTTPS provider with the same API dialect. An inspector selects the destination before the broker writes application data. Each model request carries its own decision. The existing inspection lifecycle and error semantics apply.

## Protocol and identity

A client advertising `model_routing` receives a `model_route_request` for attributed Responses, Messages and Chat Completions operations. The frame identifies the request, harness, process, Unix owner when available, path, authority and edit capabilities. A macOS Network Extension can send the effective UID from the source audit token in FlowOpen. User-mode framed senders are attributed to their Unix socket account. Windows keeps its kernel-supplied process attribution. Existing event and full-inspection clients keep their established wire format. Brokers without the new capability reject the handshake.

The inspector returns the existing correlated `inspect_response` with ordered actions. `route_provider` takes the full HTTPS operation URL. The relay opens the selected authority and port with the configured next hop, verifies its TLS identity and builds the new request head. `set_auth_headers` supplies literal field names and complete values, including subscription account headers. The fields are marked sensitive in observation and diagnostic output. `set_model` retains its original semantics. Provider actions apply to HTTP requests and WebSocket upgrades. Subsequent response creation frames can change the model on the established connection.

## Compatibility and validation

The provider must implement the operation and encoding the client uses. An HTTP/2 stream opens its own selected provider connection using HTTP/2. Client-side TLS ALPN can cause an initial handshake with the original origin. Plaintext model content is written to the selected origin. Ordinary inspections retain their existing upstream connection timing. Unattributed explicit-proxy requests and unrelated operations continue through their existing paths.

The protocol schema and its packaged SDK copy cover the routing envelope and actions. The broker suite exercises the public plugin socket, the restricted frame fields and the existing inspectors. Socket tests verify the selected HTTPS authority, alternate port, base path, model body and literal credential, alongside an unselected origin. The companion desktop client owns the configuration source, UI and per-user selections.
