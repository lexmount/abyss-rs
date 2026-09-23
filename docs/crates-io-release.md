# Publishing the broker and Rust SDK to crates.io

The public release consists of six crates, published in dependency order:

1. `abyss-plugin-protocol`
2. `abyss-storage`
3. `abyss-mitm`
4. `abyss-agent-hook`
5. `abyss-broker`
6. `abyss-sdk`

Users install the broker with `cargo install --locked abyss-broker`; Cargo
compiles its four supporting libraries as dependencies. Rust integrations add
the SDK with `cargo add abyss-sdk`; the SDK depends on `abyss-plugin-protocol`
and communicates with a separately running broker. Other workspace crates
retain `publish = false`.

## One-time setup

Log in to crates.io with the publishing owner's account and verify its email.
Create an API token with permission to publish all six names, including their
initial creation. Add it to this GitHub repository under **Settings → Secrets
and variables → Actions → Repository secrets**, named:

```text
CARGO_REGISTRY_TOKEN
```

The workflow passes the secret only to the publication step, through Cargo's
standard environment variable. It does not need `cargo login`. Pull requests
and manually dispatched runs only validate and never upload.

After the first release, add the intended maintainers or GitHub team as owners
of **all six crates**. A token's account must be an owner, directly or through
an authorized team, to publish subsequent versions.

If an existing token is restricted to the original five crate names, extend its
scope to include `abyss-sdk` and permit its initial creation before releasing.

## Prepare and release a version

Use Rust/Cargo 1.98.0 for release validation and Python 3.11 or newer. The workflow
pins Rust 1.98.0 and Python 3.12. Cargo's multi-package dry run validates the
complete dependency closure even before the supporting crates exist on crates.io.

1. Update `workspace.package.version` in the root `Cargo.toml` and the versions
   of its five publishable workspace dependencies together. Keep the lockfile
   current.
2. Update crate READMEs as needed. If the public AgentEvent fixture changes, copy
   it to `crates/abyss-broker/src/plugin/fixtures/agent-event.json`; the release check
   verifies that they match so packaged tests remain self-contained. Also copy
   the protocol's JSON schemas and fixtures into
   `crates/abyss-sdk/tests/fixtures/broker-plugin-protocol/v1/`; the same check
   rejects SDK copies that differ from the public specification.
3. Validate locally:

   ```bash
   cargo +nightly fmt --all -- --check
   python3 -m unittest discover -s scripts/tests -p 'test_publish_crates.py'
   python3 scripts/ci/publish_crates.py check --tag v1.0.0
   python3 scripts/ci/publish_crates.py dry-run --tag v1.0.0 --allow-dirty
   ```

   Replace `v1.0.0` with the intended release tag. `--allow-dirty` is only for a
   local dry run before committing. The workflow also tests and lints the six
   crates and runs the explicit proxy black-box test before packaging.
4. Commit and merge the release changes into `main`, and wait for the Rust and
   package validation workflows to pass. Existing Rust CI covers Linux, macOS,
   and Windows; the publication workflow verifies packages on Linux.
5. From the intended clean release commit, create and push its version tag:

   ```bash
   git tag v1.0.0
   git push origin v1.0.0
   ```

The `Publish broker and SDK to crates.io` workflow runs for `v*` tag pushes. It rejects
tags that do not exactly match `v<workspace.package.version>`, validates all
packages, then publishes the six crates. Cargo waits for each uploaded version
to appear in the index before publishing its dependents. Finally, the workflow
installs the exact broker version from crates.io into a temporary directory and
checks `--help` and `--version`.

GitHub's workflow dispatch is a validation-only rehearsal, including when a tag
is selected. To retry publication, use **Re-run failed jobs** on the original
tag-push run.

## Recover a partial release

Crate versions cannot be overwritten. If a job fails after some uploads, fix
external causes such as token permissions or registry availability, then rerun
the same tag-push job. The script checks the public index and skips versions
already published. A yanked version stops the release; network errors are not
treated as evidence that a crate is missing. Cargo publication failures stop
the sequence instead of continuing to dependent crates.

If source changes are needed, create a new version and tag. Do not move an
existing release tag or attempt to replace an uploaded version. Publishing jobs
are serialized across tags and are not automatically cancelled by a newer run.

For manual recovery from a clean checkout, the equivalent command is:

```bash
# Set CARGO_REGISTRY_TOKEN in the environment without adding it to the repository.
python3 scripts/ci/publish_crates.py publish --tag v1.0.0
```

See the official [Cargo publish](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)
and [GitHub Actions secrets](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets)
documentation for registry authentication and workflow configuration.
