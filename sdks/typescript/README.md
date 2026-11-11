# `@lexmount.com/abyss-sdk`

Node.js SDK for the local `abyss-broker` REST API and plugin event stream.
It does not provide browser APIs, remote event upload, or SSO handling.

Requires Node.js 20 or later.

```sh
npm install @lexmount.com/abyss-sdk
```

```typescript
import { BrokerClient } from "@lexmount.com/abyss-sdk";

const broker = new BrokerClient({ baseUrl: "http://127.0.0.1:18190" });
console.log(await broker.getProxyStatus());
```

```typescript
import { BrokerPlugin, type AgentEvent } from "@lexmount.com/abyss-sdk/plugin";

await new BrokerPlugin({ consumerId: "company.security-exporter" }).run(
  async (event: AgentEvent) => {
    console.log(event.event_id);
  },
);
```

## Publishing

The [TypeScript SDK workflow](https://github.com/lexmount/abyss-rs/blob/main/.github/workflows/publish-typescript-sdk.yml)
follows the same GitHub Release and npm trusted publishing flow as
`lexmount/abyss-dashboard`. It uses a GitHub-hosted Ubuntu runner with Node.js 24
and npm 11.5.1 or later. No additional server is required.

The SDK's major and minor versions must match `abyss-broker`; patch versions
advance independently. For example, SDK `1.0.1` can accompany broker `1.0.2`.
The workflow checks this rule on pull requests and before every release.

1. Update `version` in `package.json` and `package-lock.json` and merge into `main`.
2. Create a tag named `typescript-sdk-v<VERSION>` on that commit, for example
   `typescript-sdk-v1.0.0`.
3. Publish a GitHub Release for that tag. The workflow checks that the commit is
   on `main` and that the tag matches the package version, runs formatting,
   type checks and tests, then publishes the public package with provenance.

Pull requests and manual workflow runs only verify the package; they do not
publish. SDK tags are separate from the `v*` tags used for Rust and CLI releases.
Only stable SDK versions are supported by this workflow.

### First publication

npm requires an existing package before a trusted publisher can be configured.
An npm account with permission to publish under `@lexmount.com` must create the
first version locally. From a verified commit on `main`, complete npm's browser
login and interactive 2FA, then publish:

```sh
npm login --auth-type=web --registry=https://registry.npmjs.org
cd sdks/typescript
npm ci
npm test
npm publish --access public
```

Enter any requested 2FA verification in npm's authentication flow. Do not add
an npm publishing token or a 2FA code to GitHub Actions secrets.

After the first successful release, configure the package's **Trusted Publisher**
on npmjs.com:

| Field                | Value                        |
| -------------------- | ---------------------------- |
| Provider             | GitHub Actions               |
| Organization or user | `lexmount`                   |
| Repository           | `abyss-rs`                   |
| Workflow filename    | `publish-typescript-sdk.yml` |
| Environment name     | Leave blank                  |
| Allowed actions      | Enable `npm publish`         |

Subsequent releases authenticate through OIDC. Use a new package version for
the first CD release: the version published locally cannot be published again.
Complete the first OIDC publication within two days of creating the trust
configuration, or recreate it when ready.

See npm's [trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/)
and [interactive authentication](https://docs.npmjs.com/accessing-npm-using-2fa/).

## Request inspection

A connected request handler enables `agent_request` inspection on the existing
plugin connection. See the [request inspection example](examples/request-inspection.ts). No broker
inspector configuration is needed. Event observation is an independent capability.
Use the complete decoded body/JSON and parsing status as well as the normalized
Agent projection when implementing a policy; unknown protocols still reach the
handler. Credential headers are omitted and explicit proxy process fields are absent.
Return a safe block reason that does not contain the rejected content.

Plugins run in registration order, and each sees earlier accepted modifications.
Return Allow, Block with a safe reason, or Modify with explicit Set/Remove actions
for the selected auth token or model. `auth_token_writable` and `model_writable`
indicate supported edits. See the [model override example](examples/request-modification.ts). The SDK sends only the decision; it never diffs context.
Request handlers can read `auth_token`; event subscribers cannot.
See the [v1 wire contract](https://github.com/lexmount/abyss-rs/tree/main/specs/broker-plugin-protocol/v1).
Broker and SDKs share the updated v1 contract. A selected
plugin that fails or does not respond within five seconds fails that request.
Disconnecting the last inspection plugin restores normal streaming for future
requests. Network policy Block and opaque TLS Passthrough never invoke this callback.

### Select a model service

Return a `set_base_url` action together with model/auth actions to select a
compatible provider. The broker keeps the API operation and query, updates Host
and upstream TLS identity, and retains configured next-hop routing. It does not
translate API dialects. `context.base_url` describes the current endpoint;
`base_url_writable` is false after a WebSocket upgrade.

```typescript
return {
  action: "modify",
  actions: [
    { op: "set_base_url", value: "https://provider.example/v1" },
    { op: "set_auth_token", value: allocatedToken },
    { op: "set_model", value: "provider-model" },
  ],
};
```
