# Broker network blocking and Agent request inspection

Status: implemented. This document records the architecture and design rationale;
the original source review below is based on commit `57c29ef`. For the concrete
wire schema, limits and callback examples, see the
[plugin contract](../specs/broker-plugin-protocol/v1/README.md) and
[broker usage guide](../crates/abyss-broker/README.md).
The implementation follows the structured-session model introduced in `4e24dcf`:
request content uses `Conversation.entries`, and Harness declarations retain only
the identities actually declared by the client.

The implemented [Agent request editing extension](request-mutation-design.md)
builds on this synchronous boundary to let plugins edit semantic request fields
before forwarding.

Backward compatibility with earlier configuration and plugin protocols is not a
requirement at this rollout stage. Update the broker, delivery plugin, Rust /
TypeScript / Python SDKs, defaults, examples, and protocol fixtures together.
Use one current schema and wire format, without legacy decoders, migration
aliases, parallel protocol implementations, or compatibility adapters. The
runtime behavior specified below remains part of the design.

Implement two independent capabilities at different layers:

- **Network blocking** extends the existing TLS MITM policy with `Block`. It
  disables network flows using OS identity and destination metadata, regardless
  of whether the caller is an Agent. It requires no model parsing or plugin.
- **Agent request inspection** lets plugins inspect a decrypted model request
  before it is forwarded, for example to reject a prompt containing a private
  key. It is a broker plugin capability built on request parsing from
  `abyss-agent-hook`. Connected plugins declare the capability and the broker
  asks them for a decision over their existing connections.

The capabilities share flow metadata and transport utilities, but do not share
one rule list, action enum, or decision lifecycle. Network blocking uses the
existing MITM configuration; Agent inspection follows connected plugin capabilities.
Existing asynchronous observation hooks remain a third, independent concern.

The downstream customization point belongs to `abyss-broker`'s plugin API.
`abyss-agent-hook` supplies the shared Agent parsing and request projection;
`abyss-mitm` supplies only the transport boundary needed to wait before forwarding.
An inspection plugin does not implement or register an `abyss-mitm::MitmHook`.

**Client** means any network caller. **Agent** refers to a client in the request
inspection path; **provider** means its upstream model service. Network blocking
returns an error to the client when the transport permits one. Agent request
blocking returns an error through the already decoded application transport.

## Required behavior

1. The existing MITM policy can block by process name, destination host,
   application ID, executable path, or runtime entry point where the existing
   ingress provides those fields. Its decision uses available OS/network
   metadata, without reading model input or adding process attribution.
2. Independently, a custom plugin receives available flow identity, HTTP or
   WebSocket request metadata, complete decoded content, and a model-request
   projection. It can reject a prompt containing a private key before that
   request reaches the provider.
3. In the Agent inspection path, until all applicable plugins allow a request,
   none of its HTTP request headers or body, or its WebSocket data message, is
   forwarded. A rejected request is never partially forwarded.
4. The client receives an identifiable broker-generated rejection whenever the
   active transport can carry one. TLS establishment failures have the limitation
   described below.
5. Network blocking works with no inspection plugins connected. Agent inspection
   works with no network `block` rules configured and needs no inspector list in
   the broker configuration file.
6. TLS `Passthrough` retains its meaning: opaque traffic is relayed without
   invoking Agent inspection. Connecting an inspection plugin does not change that
   action.
7. Request buffering, model parsing, and plugin RPC are paid for only on the
   Agent inspection path. The network policy stays a concrete metadata matcher.
8. Agent inspection preserves the existing upstream connection and TLS handshake
   order. The awaited hook gates application request writes, not connection setup.
9. Streaming and inspected requests compose the same reusable transport pipeline.
   Inspection adds retention and a decision stage; it must not create a second
   implementation of request forwarding, response relay, or observation.
10. Request inspection and completed-exchange observation use one shared Agent
    parsing pipeline. Request-only access exposes reusable stages of the existing
    parser; it must not introduce a separate set of detection or extraction rules.

The Agent inspection guarantee concerns the request being checked. Upstream TCP
and TLS setup may already be complete, explicit CONNECT may already have
established a tunnel, and a WebSocket may already have an upgraded provider
connection. None establishes permission to send the pending model input.
Previously allowed requests cannot be recalled.

## Current implementation and change points

| Existing component | Current behavior | Required change |
| --- | --- | --- |
| [TLS policy:18](../crates/abyss-mitm/src/transparent/decrypt_policy.rs#L18) | `Intercept` or `Passthrough`; source and destination selectors already exist. | Add `Block` to this policy, preserving ordered rule evaluation and metadata-only decisions. |
| [Explicit ingress:146](../crates/abyss-broker/src/ingress/explicit.rs#L146) | Prepares upstream before acknowledging CONNECT; source process is absent. | Preserve the existing metadata; enforce the MITM policy, including `Block`, before releasing client application traffic. |
| [HTTP request forwarding:639](../crates/abyss-mitm/src/transparent/relay.rs#L639) | Writes the request head, then streams and captures the body. | Add a buffered inspection branch before the first upstream request write. |
| [TLS HTTP handling:123](../crates/abyss-mitm/src/transparent/tls_http.rs#L123) | Establishes provider TLS before decoding the client HTTP request. | Preserve the handshake order; gate HTTP request writes in the relay after decoding and inspection. |
| [WebSocket relay:212](../crates/abyss-mitm/src/transparent/websocket.rs#L212) | Submits an observation and forwards each client message immediately. | Await inspection before forwarding client data messages. |
| [Agent Hook coordinator:58](../crates/abyss-agent-hook/src/hook.rs#L58) | Detects and parses a completed exchange. | Refactor the existing parsing pipeline to expose request-only results shared by inspection and observation. |
| [Broker plugin server:65](../crates/abyss-broker/src/plugin/mod.rs#L65) | Owns local plugin sessions and broadcasts completed Agent events. | Extend this service with the request-inspection capability and broker-owned decision orchestration. |
| [Current plugin protocol:79](../specs/broker-plugin-protocol/v1/README.md#L79) | Best-effort, one-way live event stream; no decision replies. | Update the protocol with capability declaration and typed event/request/reply messages on the existing connection. |

An asynchronous `MitmHook` callback cannot enforce Agent request blocking. The
current dispatcher may drop observations under pressure, and HTTP callbacks run
after the exchange has already been relayed.

## Network blocking in the existing MITM policy

Add `Block` to `TlsDecryptionAction` and `TlsDecryptionDecision`, along with a
typed network-blocked flow outcome. Keep the existing
`mitm.tls_decryption` configuration and `GET`/`PUT /v1/mitm/config` API. A
network block is terminal at this layer: it does not decrypt the body, detect a
Harness, parse a model protocol, or wait for a plugin.

The proposed additions use the existing rule format:

```toml
[mitm.tls_decryption]
default_action = "passthrough"
missing_sni_action = "passthrough"

[[mitm.tls_decryption.rules]]
id = "deny-client-restricted-destination"
action = "block"
process_names = ["restricted-client"]
destination_hosts = ["restricted.example", "*.restricted.example"]

[[mitm.tls_decryption.rules]]
id = "deny-application"
action = "block"
application_ids = ["com.example.restricted-client"]

[[mitm.tls_decryption.rules]]
id = "deny-runtime-entry"
action = "block"
process_entry_points = ["/opt/example-client/main.js"]

[[mitm.tls_decryption.rules]]
id = "deny-executable"
action = "block"
executable_paths = ["/opt/example-client/bin/client"]

# Existing intercept and passthrough rules remain in the same ordered list.
[[mitm.tls_decryption.rules]]
id = "decrypt-model-api-traffic"
action = "intercept"
destination_hosts = ["api.openai.com", "api.anthropic.com"]
```

Preserve the current TLS policy semantics:

- Different populated dimensions within a rule are ANDed; values within one
  dimension are ORed. Separate rules provide alternatives.
- Host matching supports exact names and leading `*.` suffix patterns. Normalize
  hosts with the existing implementation and preserve its apex/subdomain rules.
- Process names and application IDs use exact matching. Executable paths and
  runtime entry points are distinct normalized absolute-path fields. Reuse the
  platform's path comparison rules; do not infer identity from a basename.
- An unavailable source field does not match a populated selector. An empty
  dimension is unconstrained. Keep the existing requirement for a populated
  selector on an individual rule; `default_action = "block"` expresses a default
  denial. After no rule matches, `missing_sni_action` still takes precedence when
  neither SNI nor the destination-host fallback supplies a domain. Configure
  that fallback as `block` too when a default denial must cover those flows.
- The first enabled matching rule wins across **all three actions**. A preceding
  passthrough or intercept rule can match before a later block rule. There is no
  separate deny-list priority or plugin override. Put rules in the intended order.

Reuse the current matcher and validation code, adding an executable-path selector
alongside the existing runtime-entry-point selector. Do not introduce a second
access policy or a generic policy framework.

Explicit ingress retains `source_process = None`. Rules requiring process name,
application ID, executable path, or entry point do not match that ingress;
evaluation continues to later rules and the configured fallback. Destination-only
rules and fallback actions can still select `Block` using the existing metadata.
This change does not add local process discovery for explicit proxy clients.

Evaluate at the existing flow policy boundary, after reading any required
ClientHello metadata and before forwarding client application traffic. Keep the
existing preference for TLS SNI and destination-host fallback, plus ingress
target-consistency checks. An early CONNECT rejection is valid only when the
same final decision is already established: it must not skip an earlier rule
whose SNI-dependent match is unresolved. Otherwise wait for ClientHello. No
decrypted model request is needed to decide `Block`.

Update the no-SNI-peek fast path in
[TLS routing:31](../crates/abyss-mitm/src/transparent/tls.rs#L31) as well: it
currently enters interception directly. A default-block policy must reach a
terminal network decision even when no ClientHello inspection is required.

For plain HTTP handled by the broker, apply the same ordered metadata matcher
using the validated HTTP authority/Host: a `Block` outcome denies the flow; a
non-block outcome retains the existing plain-HTTP relay behavior. Reuse the
MITM policy's rule list without adding another policy or TLS processing to
plaintext. Scope is traffic handled by the broker's HTTP/TLS ingress, not
OS-wide UDP, QUIC, file, or process control.

The following actions belong exclusively to network routing, before Agent plugin
inspection is considered:

| Network MITM action | Network routing outcome |
| --- | --- |
| `Block` | End the flow without model parsing or inspection RPC. |
| `Passthrough` | Relay opaque TLS bytes; this flow never enters Agent plugin inspection. |
| `Intercept` | Terminate TLS and decode requests. The broker can then inspect those requests through connected plugins. |

Plain HTTP that passes network policy is already readable and can enter the same
decoded request path. HTTPS inspection requires an explicit `Intercept` decision.
Connecting a plugin does not change network routing or enable TLS decryption.

The network-layer sequence is independent of Agent parsing and plugin state:

```mermaid
sequenceDiagram
    participant C as Network client
    participant B as Broker ingress and TLS engine
    participant M as MITM policy snapshot
    participant T as Remote target
    C->>B: Accepted flow and protocol preface
    B->>B: Use existing ingress metadata and required target or SNI
    B->>M: Evaluate existing ordered metadata rules
    alt Block
        M-->>B: Network block with optional rule ID
        B-->>C: Broker error where possible, otherwise close
        B->>B: Record network block metadata
        Note over B,T: No client application traffic forwarded
        Note over B,M: No model parser or Agent plugin invoked
    else Passthrough
        M-->>B: Passthrough
        B->>T: Relay opaque TLS traffic
        Note over B,T: Agent inspection plugins do not run
    else Intercept
        M-->>B: Intercept
        B->>B: Terminate client TLS and decode HTTP
        Note over B,T: Agent inspection can independently run before request forwarding
    end
```

## Agent inspection through connected plugins

This stage starts with decoded HTTP or WebSocket content. Before invoking a
plugin, the broker uses `abyss-agent-hook` to parse the request and combines the
request-side Agent projection, complete decoded content, and available metadata
into context. Opaque TLS traffic never reaches this stage. Plugins return only
allow/block decisions; they do not choose `Intercept` or `Passthrough`.

Use the existing plugin connection lifecycle. A plugin connects to the broker
and declares `agent_request` support during the handshake. The SDK can
derive that declaration from registration of an `on_agent_request` handler.
The broker then sends request context over that connection and receives an
allow/block decision with a reason. Event-only plugins keep their existing role.

No inspector list, enable flag, new runtime-policy section, or plugin management
REST API is needed. The active participants are the connected sessions that
declared this capability. A plugin's ID remains diagnostic metadata; it is not
a name the operator must duplicate in broker configuration. Custom inspection
rules belong to the plugin itself.

For each decoded HTTP request or client WebSocket data message, the broker takes
a snapshot of those sessions before choosing whether to buffer:

- With no inspection-capable sessions, use the existing forwarding path without
  request inspection, model parsing for inspection, or decision RPC.
- Otherwise, retain the complete request, parse it through `abyss-agent-hook`,
  and ask the selected sessions in connection-registration order. The first
  `Block` ends the check; all selected sessions must return `Allow` to forward.
- A plugin connected after that selection participates in subsequent requests.
  A selected plugin that disconnects before answering causes the pending request
  to fail. Future requests use the remaining connected sessions; with none left,
  they return to the ordinary forwarding path.

There is no persisted expectation that a disconnected plugin must be present.
Ordinary event consumers do not enable blocking by connecting. Plugins receive
the complete available context and implement their own model, Harness, content,
or contextual applicability logic. Unknown Harnesses/protocols still reach
selected inspection plugins with explicit parsing status.

Reuse existing body/decode and plugin frame limits as the initial bounds. Full
content must fit; an observation prefix is not a valid inspection payload.
The serialized context and request projection must also fit the existing IPC
frame limit; do not omit content to make a decision request fit.
Use a finite broker-side default decision deadline so a lost reply cannot leave
a request waiting indefinitely. These are transport implementation limits, not
a new set of per-plugin configuration options.

Keep `/v1/mitm/config` and its durable policy transaction for network decisions,
and `/v1/hooks/config` for observation. Neither stores inspection plugin membership.
Network decisions retain their existing per-flow snapshot. Plugin membership is
selected per request/message, so a newly connected plugin can inspect subsequent
messages on an already intercepted WebSocket. Opaque flows still require a new
connection and a network `Intercept` decision before inspection is possible.

Event-only plugins use the same updated handshake and message format and declare
only `agent_events`; they do not enable inspection. Update shipped configuration
and SDK consumers directly to the current contract instead of adding migration
or old-client support.

## Network routing and Agent request forwarding

```mermaid
flowchart TD
    subgraph N[OS and network layer]
        A[Flow metadata and TLS policy] --> B{MITM action}
        B -->|Block| X[Network rejection]
        B -->|Passthrough| P[Opaque relay]
        B -->|Intercept| C[Decrypt and decode HTTP]
    end
    subgraph R[Shared decoded request pipeline]
        C --> Q[Shared request preparation]
        Q --> D{Inspection-capable plugins connected}
        D -->|No| E[Streaming request body source]
        D -->|Yes| F[Retain complete request using shared body reader]
        F --> G[Broker calls abyss-agent-hook request parser]
        G --> H[Broker awaits plugin decisions]
        H -->|Allow| I[Retained request body source]
        H -->|Block or unavailable| Y[Agent request rejection]
        E --> W[Shared request writer]
        I --> W
    end
    W --> J[Shared response relay, observation, and completion]
```

### Shared pipeline composition

The branches above select how to prepare a request for forwarding. They are not
two complete relay implementations. Compose a single flow from reusable stages,
with the inspection stage present only when a request has selected plugin sessions:

| Stage | Shared responsibility | Mode-specific behavior |
| --- | --- | --- |
| Request preparation | Decode/validate the head and target, preserve prefetched bytes, determine framing, and prepare the existing header transformations. | Select streaming or inspection from the connected-session snapshot. |
| Body consumption | One framing reader owns Content-Length/chunk boundaries, trailers, completion, and captured payload extraction. | Stream validated wire bytes onward, or retain them completely within inspection limits. |
| Before-forward decision | Use the narrow transport control interface. | Streaming proceeds directly. Inspection decodes retained content, uses the shared Agent parser, and awaits broker plugin decisions. |
| Request writing | One writer emits the prepared head and original encoded body, applies existing flush/error handling, and accounts for actual upstream writes. | Consume a live body source or an allowed retained body source. |
| Response and completion | One response decoder/relay, capture and observation path, upgrade handling, accounting, and shutdown lifecycle. | Successful streaming and inspected requests rejoin this same path. Rejected requests end before request writing. |

Extract these stages from the existing relay rather than copying it into
`streaming_relay` and `inspected_relay`. In particular,
[forward_body:880](../crates/abyss-mitm/src/transparent/relay.rs#L880) currently
combines framing, capture, and writes. Separate framing consumption from its
output destination so the same parser can feed either forwarding or retention.
Keep the existing chunk/trailer validation in one implementation. Retained wire
bytes can be replayed without running the framing parser or model parser again
merely to send them.

Both modes use the same head transformation and local `100 Continue` helper.
Invoke the helper at the appropriate point for each mode, emitting it once:
inspection needs the body before any upstream request write. Request retention
does not count as upstream traffic, and replay must not duplicate capture or
observation. Reuse request-local buffers and capture metadata when available.

Keep the successful completion path represented by
[forward_http_response_and_submit:217](../crates/abyss-mitm/src/transparent/relay.rs#L217)
shared, including a WebSocket upgrade declined with a normal HTTP response.
HTTP/HTTPS share this pipeline after their existing transport setup; HTTP bodies
and WebSocket messages retain their own framing implementations.

Composition must preserve the ordinary streaming path. Do not buffer a complete
request, build an inspection projection, or impose the inspection size limit
when no inspection session was selected. Ordinary audit capture may still be
bounded or truncated without preventing forwarding; the inspected path requires
complete content. Sharing stages does not make those two retention policies equal.

### HTTP and HTTPS

Use one prepared request head and a body source consumed by the shared writer.
The source is either live streaming input or retained wire bytes. Only the
inspection branch constructs the complete retained body and decoded inspection
view; request metadata and common forwarding logic are shared.

1. Decode and validate the request head after the network decision permits this
   decoded flow. Select the connected inspection sessions before writing any
   request bytes upstream; do not re-evaluate TLS rules inside this request gate.
2. If inspection is unnecessary, compose the shared writer with the streaming
   body source, then continue through the common response/completion stages.
3. Otherwise, read the complete request body into a bounded buffer. Preserve
   Content-Length/chunked framing and already-prefetched bytes. The shared
   framing reader consumes the body for either streaming or retention.
4. For `Expect: 100-continue`, send the interim response locally to obtain the
   body. This is permission to upload to the broker, not permission to forward.
   Keep the existing removal of the locally handled `Expect` header upstream.
5. Decode content encodings and pass the complete request to the broker. The
   broker calls `abyss-agent-hook` to parse it, invokes inspection plugins, and
   returns a forwarding or rejection result to the relay.
6. On allow, pass the retained body source to the same request writer used by
   streaming requests. Preserve its body and content encoding; do not serialize
   the normalized model projection back into a provider request. Continue through
   the shared response forwarding and asynchronous observation stages.
7. On block, send a local error and close the request connection. Do not create a
   fabricated provider response or token-usage event.

Preserve the existing TCP connection, CONNECT tunnel, and TLS handshake order.
For intercepted HTTPS, the broker still completes client TLS and provider TLS
before decoding the HTTP request. Buffer and inspect the request before the
relay's first upstream request write; an established provider TLS stream does
not imply that any HTTP headers or body have been forwarded. Do not move
provider TLS setup behind the plugin decision or add deferred connection
machinery for Agent inspection. This keeps connection setup out of the work
that must run after the hook allows the request.

An early CONNECT block before `prepare_upstream()` is an optional network-policy
optimization, subject to the rule-order constraint above. The implementation
keeps existing CONNECT setup and enforces TLS blocks at the ClientHello policy
boundary, independently of the Agent gate.

The current `CapturedBody` may hold only an observation prefix. That is not an
acceptable inspection result. A request exceeding the inspection limit, an
incomplete body, or an unsupported/corrupt content encoding must terminate the
protected request before any part is forwarded. Reuse body-read/decode deadlines
where available and add a finite request-body read deadline for this branch.
There is no spill-to-disk inspection queue in the initial implementation.

For an HTTP request with inspection-capable plugins connected, the sequence is
below. The HTTPS setup illustrates the existing handshake order, which remains unchanged.
The plugin interaction represents all selected sessions in registration order;
a block or failure stops that sequence.

```mermaid
sequenceDiagram
    participant A as Agent
    participant M as MITM relay
    participant B as Broker plugin service
    participant R as abyss-agent-hook parser
    participant H as Inspection plugins
    participant P as Model provider
    opt Plugin startup, once per connection
        H->>B: Connect existing endpoint and declare agent_request capability
        B-->>H: BrokerHello confirms protocol version
    end
    Note over B,H: Context and decision replies use this same connection
    opt HTTPS setup before request inspection
        A->>M: Client TLS handshake
        M-->>A: Client TLS established
        M->>P: Provider TLS handshake
        P-->>M: Provider TLS established
    end
    A->>M: Request head and any prefetched body bytes
    M->>B: Select forwarding plan
    B->>B: Select connected inspection sessions
    B-->>M: Buffer with byte limit and opaque broker state
    opt Expect 100-continue
        M-->>A: Local 100 Continue
    end
    A->>M: Remaining request body
    M->>M: Retain full request and decode content
    Note over M,P: Zero HTTP request headers or body forwarded so far
    alt Complete content available
        M->>B: Await before-forward result with request view
        B->>R: Parse request metadata and complete content
        R-->>B: Request projection and parsing status
        B->>H: InspectRequest with parsed request and context
        alt Every applicable plugin allows
            H-->>B: allow=true
            B-->>M: Forward
            M->>P: Shared writer forwards retained request
            P-->>M: Provider response
            M-->>A: Relay provider response
            Note over M,R: Existing completed-exchange observation follows
        else A plugin blocks
            H-->>B: allow=false with safe reason
            B->>B: Record Agent request block metadata
            B-->>M: Reject with broker HTTP error
            M-->>A: 403 with broker identity and request ID
            Note over M,P: Rejected request is never forwarded
        else Selected session fails or deadline expires
            B->>B: Resolve failure and remove pending decision
            B-->>M: Reject inspection_unavailable
            M-->>A: 503 inspection_unavailable
            Note over M,P: No forwarding and no decision retry
        end
    else Body incomplete, oversized, or undecodable
        M-->>A: Broker-origin 400, 413, or 415
        Note over M,H: No allow decision from a partial body
        Note over M,P: No request bytes forwarded
    end
```

### WebSocket

The HTTP upgrade and subsequent client data messages are separate Agent decision
points on a flow already allowed by the network policy. Apply the Agent request
gate to the upgrade request when an inspection plugin is connected. Once
upgraded, select connected inspection sessions for each complete client text or
binary message before sending it to the provider, including messages that do not
produce a model response. A Responses prewarm message can still carry sensitive
input. Do not reinterpret TLS rules for each message.

Use the WebSocket implementation's message reassembly for fragmented frames and
retain its existing bounded assembly (64 MiB per message, 16 MiB per frame).
Inspect the resulting payload once;
do not forward fragments while accumulating it. Ping, Pong, and Close remain
transport control messages rather than model-input checks.

Keep one WebSocket upgrade path and one relay lifecycle. The client-to-provider
message path composes shared message reading/reassembly, an optional broker
decision, and the same message writer and observation submission. Do not create
separate normal and inspected WebSocket relay loops. Both modes share reverse
traffic handling, message ordering, counters, and close/cancellation logic.

Awaiting a plugin must not stop provider-to-Agent response/control traffic. Split
the two relay directions so the client-to-provider path waits for its current
decision while the other direction continues. Preserve client message order and
allow at most one pending inspected message per connection. A block cancels the
pending forwarding operation, closes the Agent connection with an identifiable
policy reason, and closes the provider side.
Submit the client message to observation hooks only after it is allowed; a
blocked message must not enter the normal response accumulator.

A connection already in opaque TLS passthrough cannot expose WebSocket messages.
Inspecting it requires a new connection selected for `Intercept` by network
policy. Plugin connections do not reject or reclassify opaque flows.

The following sequence starts after a successful upgrade. Provider messages in
the parallel branch may belong to an earlier allowed request; they do not imply
that the pending client message has been released.

```mermaid
sequenceDiagram
    participant A as Agent
    participant B as Broker with WebSocket relay
    participant R as abyss-agent-hook parser
    participant H as Agent inspection plugins
    participant P as Model provider
    A->>B: Client data message, possibly fragmented
    B->>B: Select connected inspection sessions and assemble within limit
    B->>R: Parse request from complete message
    R-->>B: Request projection and parsing status
    par Inspect pending client message
        B->>H: InspectRequest with message sequence and context
        alt Decision arrives
            H-->>B: Allow or Block
        else Session fails or deadline expires
            B->>B: Resolve inspection_unavailable
        end
    and Reverse direction remains active
        P-->>B: Earlier response or control traffic
        B-->>A: Continue forwarding reverse traffic
    end
    alt Every applicable plugin allows
        B->>P: Send the checked message payload
        Note over A,B: Read and check the next client data message
    else A plugin blocks
        B-->>A: Close 1008 with abyss-broker reason
        B->>P: Close provider side
        B->>B: Record Agent request block metadata
        Note over B,P: No payload from the rejected message is sent
    else Inspection unavailable
        B-->>A: Close 1011 with abyss-broker reason
        B->>P: Close provider side
        Note over B,P: Pending message is never released
    end
```

## Shared Agent parsing pipeline and plugin context

Expose request-only parsing by composing reusable stages of the existing
`abyss-agent-hook` pipeline. The request inspector and completed-exchange
observer must call the same detection, extraction, and projection code. An
illustrative `AgentRequestParser` is a facade over those stages, not a new
security-specific parser. Its `ParsedAgentRequest` is the shared request result
that can be consumed before any provider response exists.

First extract the common stages and make the existing observer use them; then
expose their request-only composition to the broker:

| Stage | Shared implementation | Composition boundary |
| --- | --- | --- |
| Input adaptation | Borrow flow metadata, HTTP/upgrade headers, path, decoded body/JSON, and completeness information. | Live HTTP, `HttpExchange.request`, and client WebSocket messages supply the same request input shape. Transport adapters do not repeat model-field extraction. |
| Recognition | Reuse Harness evidence matching, protocol detection, and provider identification. | Audit enablement is applied by the observation consumer, not by an independent inspection detector. |
| Request projection | Reuse conversation/instructions, requested model, declarations, tools, and attachment extraction. | Both consumers receive the same request-side representation and parsing status for the same input. |
| Consumer completion | Keep response parsing, exchange assembly, and event normalization as reusable later stages. | Inspection builds context from the request result. Observation combines that result with response data and applies audit retention. |

The compositions are:

```text
Inspection:  request input -> shared request stages -> plugin context and decision
Observation: request input -> shared request stages -> response stages -> audit events
```

Reuse the existing protocol-specific request projections, including
[ResponsesRequest:24](../crates/abyss-agent-hook/src/protocol/openai/responses/request.rs#L24),
[ChatRequest:18](../crates/abyss-agent-hook/src/protocol/openai/chat_completions/request.rs#L18),
and the Anthropic request parser currently called by
[exchange parsing:42](../crates/abyss-agent-hook/src/protocol/anthropic/messages/exchange.rs#L42).

Existing exchange parsers become compositions of request and response stages;
they must not retain a parallel copy of request extraction after the new facade
is introduced. Cover Responses, Chat Completions, Anthropic Messages, Claude Web
completion, and Responses client WebSocket messages. Add any missing request
fields, such as tool definitions, to the shared protocol projection rather than
an inspection-only extractor. Preserve raw content for other routes.

The current
[ProtocolDetector:36](../crates/abyss-agent-hook/src/protocol/detection.rs#L36)
accepts an exchange even though its HTTP selection uses request fields. Change
that input boundary to accept the common borrowed request view. The request-side
parts currently embedded in exchange assembly must move into the shared request
stage. For WebSocket, both inspection and the observer's accumulator consume the
same client-message projection; only response accumulation waits for a completed
turn. Keep server-message parsing in its existing response stage.

Reuse the event model's request-side primitives: `Conversation.entries` carries
text, instructions and tool calls/results in protocol order, and attachment
representations carry embedded images. Do not restore separate text or tool
projections removed by the structured-session model.
The completed audit `AgentEvent` is not the inspection input: normalization can
depend on response-derived identity, usage, and audit retention settings. The
request projection contains only facts known before forwarding; it does not
invent a response, token usage, or a completed event to fit that existing schema.
The broker combines this projection with raw content and flow context for the
inspection protocol. Response-derived model identity, correlation, and usage are
added by the later response/exchange stages using the existing precedence rules;
they do not change what was known in the request projection.

The concrete protocol parsers implement `ProtocolParser::parse_request` and
`parse_response`. `ProtocolDetector` returns a protocol enum; dispatch selects a
concrete parser without allocating a `Box<dyn ProtocolParser>`. Request and
response results live in `protocol/model`. Dialect exchange adapters call the
shared `parse_http_exchange` composition and supply their `assemble_exchange`
function. They do not call back into the request-only protocol dispatcher.

Both inspected and uninspected requests follow one logical sequence:
`parse_request -> parse_response -> assemble_exchange`. Inspection moves the
request stage before forwarding, without introducing another response parser or
exchange assembler. Without an inspector, the request stage runs at observation
time; the same response and assembly stages follow it.

Reuse decoded bytes and JSON values already available to the request stage.
All selected inspection plugins consume the same parsed result. The broker
retains `ParsedAgentRequest` after allowance using the captured body's ordinary
`http::Extensions`. Its owned `RequestContent` is shared by `Arc`; MITM only
carries opaque consumer annotations and does not import Agent types. Observation
borrows this exact request result instead of parsing it again. Without a prepared
result, it creates the request projection locally, preserving incomplete/truncated
input status and avoiding an inspection-only shared allocation. No global cache
or request-ID lookup is involved. Replacing decoded body bytes invalidates its
annotations.

For WebSocket, each inspected client data message carries its own prepared
`CapturedBody` into observation, including decoded JSON and request projection.
The upgrade request cannot supply another message's projection. Client-message
parsing reuses the prepared result, while the existing response accumulator calls
the protocol response parser and the same terminal `assemble_exchange` for both
paths. Multiple messages and turns on one connection retain their own identities.

Harness detection enriches the context but does not gate inspection. Requests
from an unknown or disabled-for-audit Harness still reach the selected request
inspector; overlapping Harness matches use the first detector in registry order.
Likewise, `hooks.harness_usage.enabled` and content
retention switches govern audit output, not the content visible to a connected
plugin that declared request inspection support.
Separate Harness evidence matching from the current audit-enabled filtering in
[HarnessRegistry:36](../crates/abyss-agent-hook/src/harness/registry/mod.rs#L36)
so reusing detection does not make inspection depend on an audit switch. Apply
audit retention to the observation output rather than mutating shared request
data used by inspection. Keep this refactoring inside `abyss-agent-hook`; the
broker assembles context and invokes plugins without duplicating protocol
detection, field extraction, or model normalization.

The proposed inspection context contains:

| Group | Fields and semantics |
| --- | --- |
| Correlation | Decision request ID, flow ID, HTTP request or WebSocket message sequence. IDs identify the broker operation, not an invented Agent turn. |
| Source | Existing ingress metadata where available: PID and process incarnation, process name, executable path, application ID, runtime entry point, working directory, and attribution source. Explicit ingress keeps source-process fields absent. |
| Destination | Original destination address, logical target authority, TLS SNI, HTTP authority/Host, ingress type, and configured upstream route metadata without credentials. |
| Request | Method, URI/path, business headers, transport, WebSocket message type and sequence, and upgrade metadata when applicable. |
| Content | Complete content-decoded bytes, an optional complete JSON value, and explicit decoding/parsing status. Binary bytes have a defined wire encoding. Original encoding metadata describes the retained encoded representation, not the decoded view. |
| Model input | Detected protocol, provider, requested model, ordered conversation/instructions, tool definitions, tool calls/results, and attachment references or inline content present in this request. |
| Agent declarations | Optional Harness identity/version, client-declared root `turn_id`, `subagent_id`, `parent_subagent_id`, and purpose. Provider continuation IDs remain in the request projection. No inferred thread/title fields. |

Provide the decoded body together with the structured model projection. The
projection is convenience data, not a complete substitute for the provider
payload: unknown JSON fields, tool schemas, historical tool output, and system
instructions can also carry secrets. Reuse decoded buffers and JSON values;
materialize the IPC representation only for selected plugins. Do not repeatedly
copy the body for each selected inspection session.

Keep provider Authorization, Cookie, and proxy credentials out of the default
plugin context. Preserve request content needed for inspection, and make any
header omissions explicit in the contract. A plugin response contains a safe
reason code/message, not a copy of the matched secret.

Use typed parsing states such as `Parsed`, `UnsupportedProtocol`, and
`InvalidModelRequest`. If the full content is available but the model protocol
cannot be recognized, still call the plugin with the complete body and status.
The plugin can scan it or explicitly reject it. Failure to obtain complete
content is a broker inspection failure and cannot become an implicit allow.

A `file_id`, external URL, or `previous_response_id` is a reference rather than
the referenced content. Include it as such. Do not reconstruct remote history or
download attachments as part of the broker gate. DLP implementations must account
for this scope when choosing what they claim to inspect.

## Shared source metadata, separate policy consumers

The existing [SourceProcess:228](../crates/abyss-mitm/src/transparent/hook.rs#L228)
already distinguishes executable path, application ID, and runtime entry point.
Reuse it and keep native process identity separate from Agent-supplied HTTP
declarations. The network matcher consumes OS metadata directly; the broker also
includes that metadata in Agent plugin context. This shared data does not imply
a shared policy or dependency on Agent parsing in the network matcher.

Preserve each ingress's current metadata capabilities. macOS/Windows transparent
ingress already supplies source metadata; explicit ingress keeps
`source_process = None`, including for local clients and `abyss run`. No
socket-owner lookup or new platform process-context provider is part of either
blocking capability.

Network rules requiring an unavailable source field continue not to match, as
they do today. Other matching rules or fallback actions still decide the flow.
Agent plugins receive the same absent source fields alongside available target,
request, and model content; absent process identity alone is not an inspection
failure. A plugin can inspect the content without process identity. Keep any
Agent-declared identity separate from OS source metadata.

## Agent inspection plugin protocol

Extend the existing broker
[PluginServer:65](../crates/abyss-broker/src/plugin/mod.rs#L65) and SDK with an
Agent request-inspection capability. The downstream extension point is an SDK
handler such as `on_agent_request(context) -> Allow | Block`; the broker calls
it through the plugin protocol. It is not a Rust `MitmHook` implementation loaded
into the transport engine. Connection membership, dispatch, pending replies,
and decision aggregation belong to the broker plugin service.

Broker callers use one `PluginServer::client()` channel handle for both kinds of
work. `PluginClient` publishes events with a best-effort `try_send`; inspection
submits an already parsed context and awaits a oneshot result. The server receives
both commands, broadcasts observations through existing sessions, and spawns a
server-owned task for each inspection. It continues accepting connections and
dispatching other commands while plugins decide. The command queue and active
inspection tasks are each bounded at 64; excess active inspections fail as
`inspection_unavailable`.

Before request retention, the client reads a `watch` snapshot of immutable
connection identities. An empty snapshot preserves streaming with no inspection
context construction or RPC. A nonempty snapshot becomes an opaque
`InspectionPlan`: no registry, session object, or session sender escapes the
plugin service. The server resolves those identities and performs ordered
inspection internally. Connections added after selection do not join that request;
a selected connection that disappears fails it even if the same plugin reconnects.

Keep the existing Unix socket/Named Pipe endpoint and length-prefixed JSON
framing. Update the protocol on that same connection with capability declaration.
A plugin declares `agent_request` when it supplies an
inspection handler, and may also declare `agent_events` to receive observations.
It does not need a second connection or a separate inspection endpoint.

The current
[PluginSession handshake:149](../crates/abyss-broker/src/plugin/session.rs#L149)
uses a strict hello followed by direct event payloads. Replace that shape with
one current hello schema and a tagged message format for events, inspection
requests/replies, and close/error messages. All consumers, including event-only
plugins, adopt this format. A protocol-version field can detect a mismatched
build; it does not select an older decoder, fallback format, or compatibility mode.
Keep the current local endpoint access model; this feature adds no plugin token
files, allowlist, or authorization configuration. `plugin_id` remains a diagnostic
label, while request/reply routing is tied to the actual connected session.

The minimal inspection exchange is:

```text
Plugin -> Broker: PluginHello(protocol_version=CURRENT_VERSION, plugin_id, capabilities=[agent_request])
Broker -> Plugin: BrokerHello(protocol_version=CURRENT_VERSION)
Broker -> Plugin: InspectRequest(request_id, context)
Plugin -> Broker: InspectResponse(request_id, allow, reason?)
```

`allow = true` permits forwarding; `allow = false` rejects with the supplied
safe reason, or a generic broker rejection if no reason is supplied. The SDK can
expose a typed `Allow` / `Block { reason }` enum while
the wire carries the boolean and optional reason. The broker owns the stable
`agent_request_blocked` error code and response envelope. A missing or invalid
decision is not an implicit `true`. `Passthrough` and `Intercept` are not plugin
response values; request content has already been decoded and parsed before
this exchange, with explicit parsing status for unsupported or invalid protocols.

The existing [PluginSession:69](../crates/abyss-broker/src/plugin/session.rs#L69)
enters a write-only event loop after its handshake. Replace it with a session
reader for replies and one serialized writer for outbound events and inspection
requests. Reuse event delivery for observations, but send live decision requests
through a bounded session channel instead of the best-effort event broadcast.
Associate each pending request with a oneshot reply and its session. This permits
concurrent request IDs without holding a mutex across I/O or a decision await.

The internal five-second deadline per selected session covers queueing,
transmission, and the reply. Server command queueing consumes the first session's
budget. Dropping the caller's reply receiver cancels the server inspection task;
server shutdown drops queued replies and stops active tasks before closing sessions. A
selected session's full queue, disconnect, timeout, malformed reply, or handler
error rejects its pending request as `inspection_unavailable`. Remove pending
entries on completion or cancellation; late replies are ignored. Disconnecting
removes the session from future participant selection and resolves its outstanding
waiters. A reconnect creates a new session, not a replacement answer source for
old requests. There is no retry or persisted replay of a live decision.

With no inspection-capable session selected, there is no inspection RPC and no
missing-plugin failure. A plugin's answer controls only the request being checked;
it does not change TLS policy or install broker network rules. These connection
and reply rules are sufficient for the initial capability; no separate plugin
configuration or lifecycle management service is required.

## Rust boundaries and zero-cost abstractions

Keep the existing concrete TLS policy matcher and its `Block` branch in
`abyss-mitm`, with network rejection handling at the relevant ingress/transport
boundary. This path has no request-inspection trait, plugin dispatch, or Agent
dependency. `TlsDecryptionAction` and `TlsDecryptionDecision` remain network
types with `Intercept`, `Passthrough`, and `Block` outcomes.

Separately, keep request transport gating in `abyss-mitm`, parsing in
`abyss-agent-hook`, plugin orchestration in `abyss-broker`, and language-neutral
inspection messages in `abyss-plugin-protocol`:

| Owner | Responsibility |
| --- | --- |
| `abyss-agent-hook` | Shared Harness/protocol detection and request parsing, with both pre-forward request projections and existing observation consumers. |
| `abyss-broker` | Connected plugin capabilities, parser invocation, request/reply dispatch, decision aggregation, and broker error mapping. |
| `abyss-plugin-protocol` and SDKs | Typed inspection context/replies and the downstream custom handler contract. |
| `abyss-mitm` | Existing TLS/network decisions, HTTP/WS framing, request retention, and the mechanical wait/forward/reject boundary. |

MITM must not import broker, Agent parsing, or plugin protocol types. It does not
know which model or plugin is being inspected. The broker's private
`proxy::request_control::RequestControl` connects transport input to
`abyss-agent-hook`, submits the prepared context through `PluginClient`, and maps
the returned decision into a transport result. `plugin::inspection` remains
private and owns session selection, encoding, pending replies, and aggregation.

The relay still needs a point at which its caller can await a result before
writing upstream. Keep that a narrow transport integration interface, separate
from `MitmHook` and its asynchronous observation dispatcher. Do not add an Agent
plugin registry or a blocking callback to the existing MITM hook chain.

The transport interface can have the following shape; names are illustrative:

```rust
enum ForwardingPlan<P> {
    Stream,
    Buffer { max_bytes: usize, state: P },
}

enum ForwardingDecision {
    Forward,
    Reject(LocalRejection),
}

trait RequestForwardingControl: Send + Sync {
    type Plan: Send;

    fn plan(&self, flow: &FlowContext, head: &Request<()>)
        -> ForwardingPlan<Self::Plan>;

    fn before_forward<'a>(
        &'a self,
        plan: Self::Plan,
        request: RequestView<'a>,
    ) -> impl Future<Output = Result<ForwardingDecision, ForwardingError>> + Send + 'a;
}
```

`RequestView` borrows flow metadata and complete decoded content. The associated
plan carries an opaque snapshot of selected connection identities
without exposing those types to MITM. The WebSocket entry uses the same decision types
with a message view and upgrade metadata. `LocalRejection` contains only the
transport response/close information needed by the relay; the broker owns the
Agent rejection code and message. The transport plan chooses streaming or
buffering, without Agent concepts, network block rules, or plugin IDs.

Interpret `ForwardingPlan` at request preparation and body consumption, rather
than branching into two full relay functions. Compose the shared request writer
with a live or retained body source, then call the same response/completion
stages. The plan's only inspection-specific work is retaining full content and
awaiting the broker's before-forward result.

`RequestControl::before_forward` calls the shared Agent request parser,
builds plugin context, awaits the plugin server through its channel client, and maps its
`Allow`/`Block` result to `Forward`/`Reject`. It does not call the observer's
`on_http_exchange` with a fabricated response. An Agent `Allow` authorizes this
request within an already intercepted/decoded flow and never overrides a network
decision.

After Allow, the prepared request remains attached to the captured body for the
existing observation worker to reuse. With no inspector, Agent request/response
parsing and exchange assembly remain in that background worker. This refactor
keeps the current eager JSON initialization in `CapturedBody`; moving that step
off the forwarding path is outside its scope.

Pass `G: RequestForwardingControl` through the relevant engine/relay methods so
Rust monomorphizes the calls and futures. Keep the engine and unrelated control API
structures concrete; they do not all need a new generic parameter. Update engine
call sites directly where needed; use a streaming-only control for callers that
do not inspect requests, without a legacy entry-point wrapper.

Implement stages as concrete structs with `impl` methods and shared functions;
use static generics where stream/body-source behavior varies. This is composition
of the existing transport operations, not a new pipeline framework. Avoid a
runtime list of boxed stages, type-erased stage context, or a generic workflow
graph. Keep HTTP and WebSocket framing concrete while reusing broker decision
orchestration and shared transport helpers.

Use a concrete `Vec<InspectionPluginClient>` for connected inspection sessions.
They all use the same IPC implementation; their custom logic runs in
separate processes. Avoid a new `Vec<Box<dyn BlockHook>>`, boxed per-call futures,
an `Any` extension bag, or a callback on every body chunk.

The streaming-only implementation can inline to the existing relay. The broker
still checks connected inspection sessions and retains the selected handles;
zero-cost abstraction does not eliminate that work. Active inspection pays for complete
request buffering, parsing, serialization, IPC, and plugin execution. Reuse
`Bytes` and borrowed views, decode once, and share request parsing functions with
the observer. Compose shared parser stages using concrete types and ordinary
function calls, just as for the transport pipeline. Reuse request-local parsed
results when their ownership is already available; do not add a global cache,
boxed parser-stage list, or cross-task framework to enforce one parse across
otherwise independent asynchronous consumers.

## Rejection responses and recording

Keep network and Agent outcomes distinct. The broker owns both response
envelopes and may reuse HTTP formatting helpers. Plugins return `Allow` or an
Agent inspection block reason, not network actions, arbitrary HTTP responses,
or modified provider requests.

When an HTTP transport is available, return `403 Forbidden`,
`Content-Type: application/json`, `Server: abyss-broker`,
`X-Abyss-Blocked: true`, `Cache-Control: no-store`, a correct Content-Length,
and `Connection: close`. A network rejection before CONNECT succeeds, or on
plain HTTP, identifies the flow and the matched network rule:

```json
{
  "error": {
    "type": "abyss_network_policy",
    "code": "network_blocked",
    "message": "Network connection blocked by abyss-broker",
    "flow_id": "flow-example",
    "rule_id": "deny-application"
  }
}
```

Omit the rule ID when `default_action` or `missing_sni_action` selected the block.
An Agent plugin rejection uses request correlation and a separate error code:

```json
{
  "error": {
    "type": "abyss_agent_policy",
    "code": "agent_request_blocked",
    "message": "Request blocked by abyss-broker: private key detected",
    "request_id": "req-example"
  }
}
```

Within the Agent path, distinguish a policy rejection from inability to inspect.
Failure of a selected plugin call returns broker-origin `503` with `inspection_unavailable`;
an oversized inspected request returns `413` with `inspection_limit_exceeded`.
Invalid framing/content encoding uses an appropriate `400`/`415` error with the
same broker identity and request correlation. None of these outcomes forwards
the protected request.

| Rejection point | Client-visible behavior |
| --- | --- |
| Network block at explicit CONNECT, before success | Return `403 network_blocked`; do not establish the target tunnel. Some clients display only the status. |
| Network block on plain HTTP | Return `403 network_blocked` before forwarding application bytes. |
| Network block after ClientHello, including transparent TLS and acknowledged CONNECT | Terminate before forwarding client application traffic. The client sees a TLS/socket failure, not a JSON body. Expose the typed reason through broker diagnostics and ingress control messages where available. |
| Agent block on plain HTTP or successfully intercepted HTTPS | Return `403 agent_request_blocked` through the decoded client stream; no bytes of that provider request are sent. |
| Failed TLS interception, including untrusted MITM CA or pinning | Agent inspection never runs. Report the transport failure; do not label it an Agent plugin rejection. |
| Agent block before WebSocket upgrade | Return an HTTP Agent rejection. |
| Agent block after WebSocket upgrade | Send Close code `1008` with a short reason such as `abyss-broker: agent_request_blocked <id>`, then terminate the provider side. Use `1011` for inspection infrastructure failure. |

A network `Block` must not perform MITM solely to synthesize an HTTP error.
There is no application error channel inside a TLS connection the broker has
not established. For platform ingress, propagate `network_blocked` with flow
correlation through existing flow-close/control facilities, such as
[macOS FlowClosePayload:463](../crates/abyss-broker/src/ingress/macos/framed_protocol.rs#L463),
in addition to local diagnostics. This makes the reason explicit to the adapter;
arbitrary applications may still present only a connection error.

WebSocket close reasons must fit the control-frame limit. Do not invent provider
application events to carry a rejection. A later protocol-specific error encoder
can improve individual Agent UX, but the initial contract guarantees an explicit
broker reason on decoded application transports, not identical UI presentation
in every client.

Represent `NetworkBlocked` and `AgentRequestBlocked` as distinct typed outcomes,
separate from provider failures. Network records contain flow ID, MITM rule ID
or fallback source, and available OS/target metadata. Agent records contain flow
and request/message IDs, plugin ID, safe reason code, and inspection timing.
Neither record depends on the other capability being active. Record that the
blocked flow/request's application payload was not forwarded.
Keep transport byte counters accurate: TCP/TLS/tunnel setup traffic is distinct
from the rejected application's request bytes.
Reuse the existing storage and diagnostics surfaces. Do not publish a rejected
prompt as an ordinary completed usage event, upload its sensitive content through
delivery, or attach secret excerpts to diagnostic messages. A separate security
event export can be added if a consumer requires it.

## Implementation sequence and acceptance criteria

Implement the network extension independently; it can ship without Agent
inspection. For the Agent capability, HTTP and WebSocket protection are both
required parts of the final feature.

1. **Network policy block.** Extend the existing TLS action/decision enums,
   selectors, validation, config/API contracts, and SDK representations. Add the
   terminal block branch, update routing fast paths, and implement ingress errors
   and flow-close reasons. Preserve existing rule order and durable MITM updates.
   Preserve existing ingress metadata, including absent explicit-proxy process
   information; add no process discovery.
   No Agent parser or plugin change is needed to enable this capability.
2. **Shared Agent parsing and HTTP forwarding boundary.** Refactor request-side
   detection, extraction, and projection into common stages in `abyss-agent-hook`.
   Route existing exchange/WebSocket observation through those stages, then expose
   the request-only composition for inspection. Extract the common request
   preparation, framing reader, writer, and completion stages. Compose streaming input or
   buffered inspection into those stages, with local rejection before the first
   upstream request write. Do not duplicate the existing relay implementation.
   Preserve the existing upstream connection and TLS handshake order. Use a
   concrete in-process transport control to verify the forwarding boundary.
3. **Broker plugin inspection.** Update the current protocol on the existing
   endpoint with capability declaration, connection membership, tagged messages,
   and SDK handlers. Update all SDKs, the delivery plugin, specs, and fixtures
   together; implement no legacy protocol path. Use a private request control
   adapter for the shared parser and a channel-only `PluginClient` for decisions.
   Keep connected-session dispatch inside `PluginServer`. Add no plugin configuration
   section or management API.
   Add a minimal DLP plugin example; private-key detection belongs in that custom
   plugin rather than a broker or MITM security-rule catalog.
4. **Agent WebSocket inspection and integration.** Add the optional decision
   stage to the common client-message pipeline. Reuse message writing, observation,
   reverse-direction progress, and cancellation/close handling for both modes,
   then run the same plugin through real broker traffic.

Acceptance tests should prove the boundary, not merely check decision enums:

- Block a non-Agent network client with no inspection plugins connected.
  Exercise all three TLS actions in one ordered rule list, including
  an earlier passthrough/intercept rule before a later block. Test default block,
  missing-SNI fallback, destination-host fallback, and the no-SNI-peek fast path.
  An early CONNECT optimization must not skip an unresolved earlier rule.
- Connect an inspection-capable plugin with no network block rules and verify a
  private-key request is rejected on an intercepted flow. With the same plugin
  connected, verify passthrough flows still relay opaque bytes without Agent
  parsing or RPC. Neither capability changes the other's role.
- With no inspection-capable plugin, verify ordinary forwarding with no inspection
  buffering or RPC. Event-only plugin connections must not enable inspection.
  Verify that connecting a plugin requires no broker configuration edit.
- Use a mock provider that records bytes received. For a blocked HTTP request,
  assert zero provider HTTP request bytes, including the head and any prefetched
  body. Cover explicit HTTP/CONNECT and platform ingress, direct and configured
  upstream routing. Separately account for permitted TCP/TLS/tunnel handshakes.
- For intercepted HTTPS, verify provider TLS still completes before Agent
  inspection runs. While the hook is pending and after a rejection, the provider
  must receive zero HTTP request bytes even though its TLS connection exists.
- Use one set of Agent parser fixtures and expected request projections for
  request-only inspection, completed-exchange parsing, and applicable client
  WebSocket messages. Compare conversation/instructions, tools, requested model,
  declarations, attachments, and parsing status across the entry points. Include
  unknown fields and incomplete observation captures. Verify audit filtering
  leaves the shared request projection unchanged and does not affect inspection
  invocation. Response-derived fields appear only in the later response/exchange
  stages. Inspection needs no
  fabricated response or completed usage event; its custom handler registers
  with the broker plugin service rather than the MITM observation hook chain.
- Place a private-key-shaped fixture near the end of a request, across chunk
  boundaries, in compressed JSON, instructions, tool output, and unknown JSON
  fields. The inspector must see the full relevant content before any forwarding.
- Check Content-Length, chunked bodies, prefetch, `Expect: 100-continue`, empty
  bodies, decode failures, read deadlines, and inspection limits. An oversized
  request must never be allowed using a truncated prefix.
- For allowed requests, verify the provider receives the original payload under
  the existing relay transformations and the Agent receives its normal response.
  Existing capture/token-usage behavior must remain valid.
- Run the same forwarding fixtures through streaming and inspected-allow modes.
  Compare provider-visible headers/body, client-visible response, wire byte counts,
  capture completeness, and normalized content/usage. Cover Content-Length,
  chunked trailers, prefetch, `Expect: 100-continue`, compression, and successful
  or declined WebSocket upgrades. Assert one observation per completed exchange
  or allowed message, with no duplicate capture/accounting from retained replay.
  Separately verify that ordinary audit capture limits still permit streaming
  requests larger than the inspection limit.
- For WebSocket, block a fragmented data message and a later request on an
  already-used connection. Assert no bytes from that message reach the provider,
  earlier allowed messages remain accounted for, prewarm input is checked, and
  provider responses/control traffic progress during a pending inspection.
- Exercise unknown Harness/protocol cases and disabled audit-content settings.
  None may silently bypass selected inspection sessions on decoded traffic.
- Exercise timeout, disconnect, queue saturation, malformed and late replies,
  and Agent cancellation for selected sessions. Assert a terminal result,
  pending-state cleanup, and zero rejected-request forwarding. After the last
  inspector disconnects, verify later requests use ordinary forwarding; the
  failed in-flight request must not become allowed by dropping its waiter.
- Test selector AND/OR semantics, unavailable source metadata, executable versus
  entry-point identity, SNI/Host/CONNECT consistency, and next-hop versus target
  hostname. Verify process rules against metadata already supplied by platform
  ingress. For explicit ingress, verify source-process fields remain absent,
  process-dependent rules do not match, and destination-only or fallback blocks
  still work. Verify Agent plugins can inspect decoded requests with absent
  source-process fields.
- Validate the current handshake, tagged event messages, and decision replies
  across Rust, TypeScript, and Python, including the updated delivery plugin and
  a session receiving events and inspection requests on one connection. Verify
  replies are matched to their request and session, including reconnects and
  concurrent requests. Check shipped configuration examples against the current
  schema and retain MITM/observation policy update tests. No legacy-format
  interoperability suite is required. Plugin membership changes apply to
  subsequent requests/messages and cannot reclassify passthrough flows.

Measure throughput and allocation changes with no inspectors connected,
network block rules active, and inspectors connected. With no inspectors,
network decisions must not allocate inspection buffers, serialize
model requests, or start decision workers. Report active inspection
latency separately from relay overhead. These measurements validate the intended
abstraction cost without expanding this change into a new performance framework.

## Real Codex SDK inspection regression

`make test-blackbox-sdks-codex` runs the actual Codex CLI against OpenAI through
an isolated explicit-proxy broker and each language's public SDK. It requires
`CODEX_API_KEY`, the pinned Codex CLI used by CI, and installed TypeScript build
dependencies. No backend, system trust-store change, or private-key detection is
involved. The temporary CA is supplied only to the Codex child process.

The Rust, TypeScript, and Python participants all declare both `agent_request`
and `agent_events` on one connection. For each SDK the runner checks:

- A real Codex request reaches the callback with the decoded JSON, normalized
  request entries, Codex identity, model, TLS target, absent explicit-proxy process
  attribution, and credential headers omitted.
- A marker in the parsed request selects Block. Codex exits with a failed turn,
  HTTP 403, and the plugin's exact reason. Codex displays `error.message`, so its
  console output is not expected to reproduce the complete broker JSON envelope.
- A different marker selects Allow on the same plugin connection. Codex completes
  against the real provider and returns that marker. The SDK receives correlated
  request/response events with a response ID and nonzero output usage.
- The blocked prompt produces no observed request/response exchange, and broker
  shutdown cleanly closes the SDK session.

The `Codex Black-box` workflow runs this target on same-repository pull requests,
main pushes, and manual dispatch. It uses the repository's `CODEX_API_KEY` secret;
fork pull requests cannot run this credentialed job. Provider concurrency follows
the existing OpenAI CI queue. Artifacts contain sanitized results and, on failure,
metadata-only SDK evidence. Raw prompts, credential values, and temporary CA keys
are not uploaded.

To select one SDK, set `SDK_CODEX_ARGS="--sdk rust"` (or `typescript` / `python`).
`--block-only` is a separate local rejection smoke test; its results explicitly
report that live provider completion was not verified. CI does not use that mode.
The regular `make test-sdks` remains credential-free, and existing deterministic
HTTP / gzip / WebSocket broker tests continue to cover transport-level behavior.
