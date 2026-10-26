# abyss-terminal-auth

Shared terminal authentication contracts for Rust command-line applications.
This library provides PKCE material generation, the `/auth/terminal/start`,
`poll` and `exchange` DTOs, native-session identity/revocation contracts, a
synchronous control-plane client, and file-credential helpers.

Deployment endpoints are always supplied by the caller. Applications own
profile selection, browser instructions, transport policy, secure credential
storage and machine-readable output. There is no refresh-token contract;
a caller must initiate a new login after its native session expires.

`abyss-query-cli` reuses the PKCE and wire DTOs with its bounded HTTP transport
and platform keyring persistence. Existing applications can continue using
`TerminalLoginAttempt`, `ReqwestControlPlaneAuthClient` and
`FileCredentialStore` directly under their own transport/storage policy.

```rust
use abyss_terminal_auth::TerminalLoginMaterial;

let material = TerminalLoginMaterial::generate();
assert!(!material.state().is_empty());
assert!(!material.code_challenge().is_empty());
// Keep the verifier private; only send it when exchanging the completed attempt.
```
