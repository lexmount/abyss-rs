# Configured MITM redirects

A `redirect` rule selects an HTTP(S) upstream origin before Abyss resolves or
connects the destination. It uses the existing MITM policy alongside `block`,
`passthrough`, and `intercept`. Routing belongs to MITM configuration; Agent
plugins continue to modify semantic request fields such as credentials and model.

## Configuration and behavior

```toml
[[mitm.tls_decryption.rules]]
id = "openai-to-deepseek"
action = "redirect"
destination_hosts = ["api.openai.com"]
target = "https://api.deepseek.com"
```

The first enabled matching rule wins. Existing source-process and destination
selectors keep their semantics. Match the original destination, once per flow;
do not evaluate the target against the rules again. Place this rule before any
broader matching intercept or passthrough rule. Explicit clients do not supply
source-process identity, so use destination selectors for that ingress.

`target` is an HTTP(S) origin: scheme, host, optional port, and optionally a
trailing `/`. Paths, query strings, fragments and embedded credentials are not
accepted. Only redirect rules may specify it, and every redirect rule requires
it. `default_action` and `missing_sni_action` cannot be `redirect`; use a matching
rule with a target. Invalid updates leave the published policy unchanged.

| Request property | Redirect behavior |
| --- | --- |
| Destination DNS/TCP or upstream CONNECT target | Use the configured target, without contacting the original destination |
| Upstream TLS | Target scheme selects TLS; verify the target host with existing provider trust |
| Client TLS | Intercept using the original client SNI and the Abyss CA |
| Request URI origin and Host | Replace with the target origin and authority |
| Method, path and query | Preserve, including escaping |
| Other headers and body | Preserve unless an existing plugin modifies them |
| WebSocket | Redirect the HTTP upgrade; keep that connection for subsequent frames |
| Configured next-hop proxy | Retain its TLS, authentication and timeouts; replace only its CONNECT destination |

The rule works for plain HTTP and intercepted HTTPS, including HTTP-to-HTTPS and
HTTPS-to-HTTP targets. HTTPS retains the existing interception requirements,
including usable client SNI and client trust in the Abyss CA. It does not translate
model protocols, rewrite paths, select keys or choose models. For example,
`/v1/responses` remains `/v1/responses`; a target must support the client's API.
No plugin protocol or plugin decision variant is added. Plugin context retains
original flow metadata (`destination_host` and client `server_name`), while the
request authority and parsed provider reflect the selected target. Auth plugins
can therefore scope their edits to the effective provider.

## Flow

```mermaid
sequenceDiagram
    participant A as Agent
    participant I as Broker ingress
    participant M as MITM
    participant P as Configured next hop (optional)
    participant T as Redirect target
    participant H as Agent Hook and plugins
    A->>I: CONNECT original.example:443
    I-->>A: 200 Connection Established
    I->>M: Client IO, original metadata, next-hop snapshot
    A->>M: TLS ClientHello (original.example)
    M->>M: Validate original target and match redirect rule
    M-->>A: Client TLS using original.example certificate
    A->>M: HTTP request head
    M->>M: Validate original Host; replace URI origin and Host
    alt Configured next hop
        M->>P: Connect proxy; authenticate CONNECT target.example:443
        P->>T: Open selected target tunnel
        P-->>M: Tunnel established
    else Direct
        M->>T: Resolve and connect selected target
    end
    M->>T: Upstream TLS for target.example (HTTPS target)
    T-->>M: Certificate verified with provider trust
    M->>H: Parse request and inspect semantic context
    H-->>M: Allow / Block / Modify actions
    M->>T: Forward allowed request with any token/model edits
    T-->>M: Response
    M-->>A: Response
```

For plain HTTP, decode the head and match the original Host without the client
TLS steps. Passthrough TLS still connects the original target and relays opaque
bytes. Blocked flows do not establish an upstream connection.

Explicit CONNECT's 200 response acknowledges the **local tunnel**. Upstream
establishment follows protocol detection and policy selection. Once an HTTP head
is available, connection failures return a local 502 (or 504 for timeout, 403 for
a listener loop). Opaque TLS failures close the tunnel. Proxy authentication
challenges and response bodies are not forwarded as provider responses. Existing
network diagnostics retain the transport failure and connected proxy peer.

## Implementation boundaries

- `abyss-broker::ingress::explicit` decodes the proxy request, acknowledges CONNECT
  and supplies original metadata plus the selected next hop. It does no target DNS
  lookup or TCP/CONNECT establishment.
- `abyss-mitm::transparent::decrypt_policy` validates redirect configuration and
  selects the target with the existing ordered policy.
- `transparent::redirect::RedirectTarget` parses origins and rewrites the request
  head. It contains no Agent or model-provider knowledge.
- `transparent::upstream::HttpUpstream` combines the selected destination, next hop
  and upstream TLS identity. Direct logical targets resolve at this boundary;
  unchanged native transparent flows retain the OS destination address.
- `DecodedClientFlow` in `relay.rs` applies the route and opens the selected
  connection. `RequestRelay` encodes a changed head while retaining the original
  body framing. Existing Agent parsing and mutation handle the remaining request.

Configuration uses the existing `GET/PUT /v1/mitm/config` and durable
`runtime-policy.toml` transaction. Changes affect new flow decisions; active SSE
or WebSocket streams retain their selected destination. REST SDKs expose the new
rule action and `target` field. Plugin protocol v1 is unchanged.

## Codex with DeepSeek

The example [codex_deepseek_auth.py](../sdks/python/examples/codex_deepseek_auth.py)
reads `~/.deepseek/api.key` once and supplies the token and `deepseek-flash` model
only for Codex requests whose selected authority is `api.deepseek.com`.
`DEEPSEEK_API_KEY_FILE` and `DEEPSEEK_MODEL` override these defaults. Run it with
`PYTHONPATH=sdks/python` and `ABYSS_BROKER_STARTUP_INFO` pointing to the isolated
broker's startup-info file. Keep it running while Codex uses the explicit proxy.
The plugin neither changes the destination nor persists or prints the key.

Keep Codex's Responses endpoint at `https://api.openai.com/v1`, give it a placeholder
credential, and configure the redirect rule above. Set `HTTP_PROXY`, `HTTPS_PROXY`,
`CODEX_CA_CERTIFICATE` and `SSL_CERT_FILE` only for the test child process; the CA
need not enter the system trust store. The current
[DeepSeek Codex guide](https://api-docs.deepseek.com/quick_start/agent_integrations/codex/)
describes its native Responses support.

Verification with real Codex CLI 0.167.0 succeeded with `/v1/responses` unchanged, upstream
TLS to `api.deepseek.com`, model `deepseek-flash`, and a token equality check against
the local key. Codex returned the requested marker after HTTP 200. The equality
check records booleans, never the credential. Automated tests separately exercise
unreachable original destinations, TLS identity separation, raw body retention,
plugins, WebSockets, policy persistence and authenticated HTTPS proxy routing.
