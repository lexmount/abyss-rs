# Public CLI binary releases

The public CLI distribution installs the open runtime's three programs without
requiring Rust on the user's machine. It supports macOS ARM64 and Linux x86_64
with systemd. The Linux archive uses musl to avoid a dependency on the build
machine's glibc version. It still requires systemd and the system CA trust tools
used by the CLI runtime. Other architectures use `scripts/install-cli.sh`.

## User installation

After the first complete CLI release is published:

```sh
curl --proto '=https' --tlsv1.2 -fsSL \
  https://github.com/lexmount/abyss-rs/releases/latest/download/install.sh | sh
abyss version
```

The downloaded script is POSIX `sh`, with its own release version embedded at
packaging time. Archive and checksum URLs always use that exact version, even
if a newer release becomes latest during installation. `--version 1.0.0` selects
another stable release. Use `sh -s -- --prefix /opt/abyss` to choose a prefix.
Prefixes accept letters, digits, slash, underscore, dot, and hyphen. All three
binaries are installed together; Linux's unit is written to
`/etc/systemd/system/abyss-broker@.service` with the selected executable path.
Add `PREFIX/bin` to PATH when using a custom prefix. The Linux service assumes
the default `/home/<user>/.abyss` state directory.

Download, SHA-256 verification, unpacking, and executable smoke checks happen
before installation. Only installation requests sudo, using the terminal for
authentication even when the script is piped through stdin. `DESTDIR` stages an
installation without contacting systemd. Stop Abyss before an upgrade; the
installer does not stop or start services and preserves existing user data.

With Node.js 22+ and npm 10+ available, initialize the local environment:

```sh
abyss deploy-local start
abyss run -- codex
```

## Release assets

For version `1.0.0`, publish these four assets in one release:

```text
install.sh
SHA256SUMS
abyss-cli-v1.0.0-aarch64-apple-darwin.tar.gz
abyss-cli-v1.0.0-x86_64-unknown-linux-musl.tar.gz
```

Each archive contains `abyss`, `abyss-broker`, `abyss-delivery-plugin`,
`abyss-broker@.service`, `VERSION`, and `LICENSE`. Deployment configuration,
backend, and dashboard are prepared separately by `abyss deploy-local`.
The Git tag identifies the corresponding source available from GitHub's source
archive. The binaries remain covered by this repository's GPL license.

## Build and publish

`.github/workflows/cli-release.yml` builds both targets, exercises the download
installer, packages the runtime, and installs the real packaged binaries into
a temporary staging root. Pull requests and manual dispatches only validate
and upload Actions artifacts. The smoke test uses local release assets as the
download transport; the public URL is available only after publishing.

1. Update the workspace version and dependencies as described in the
   [crates.io release guide](crates-io-release.md). CLI packaging rejects a tag
   that differs from the workspace version and only accepts stable versions.
2. Run `make test-install-cli` and merge the tested change into `main`.
   Run the CLI release workflow manually to rehearse both native builds.
3. Create and push the matching `v<version>` tag from the intended release
   commit. This also triggers the existing crates.io publication workflow;
   ensure its registry token and release prerequisites are ready.
4. The CLI publication job waits for both packages, verifies their checksums,
   creates a draft GitHub Release, uploads every asset, and only then publishes
   it as latest. Its `GITHUB_TOKEN` needs `contents: write`; no new secret is
   required for CLI assets.

A failed upload leaves the release as a draft, allowing the original workflow
run to be retried. Published releases are never overwritten by the workflow;
source changes require a new version and tag. Serialize release tag pushes and
wait for each release to finish before starting another version.

For a local packaging rehearsal after compiling the three release binaries:

```sh
python3 scripts/ci/package_cli.py --target aarch64-apple-darwin \
  --binaries target/aarch64-apple-darwin/release --output /tmp/abyss-cli-release
cat /tmp/abyss-cli-release/SHA256SUMS.* > /tmp/abyss-cli-release/SHA256SUMS
sh scripts/tests/smoke_release_install.sh /tmp/abyss-cli-release
```

Use `x86_64-unknown-linux-musl` on Linux, with the Rust target and `musl-gcc`
installed. Packaging requires Python 3.9+ and Cargo but performs no compilation.
