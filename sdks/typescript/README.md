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
For the first release, add a short-lived granular access token as the repository
Actions secret `NPM_TOKEN`. The account must be allowed to publish packages under
`@lexmount.com`. In **Packages and scopes**, grant **Read and write (publish and
stage)** for the `@lexmount.com` scope and enable **Bypass 2FA**. Organization
management permissions alone do not grant publishing access.

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

Remove the `NPM_TOKEN` GitHub secret and revoke the temporary token. Subsequent
releases authenticate through OIDC. Complete the first OIDC publication within
two days of creating the trust configuration, or recreate it when ready.

See npm's [trusted publishing documentation](https://docs.npmjs.com/trusted-publishers/)
and [token configuration](https://docs.npmjs.com/creating-and-viewing-access-tokens/).
