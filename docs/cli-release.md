# Endpoint binary releases

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

For version `1.0.0`, publish these seven assets in one release:

```text
install.sh
SHA256SUMS
abyss-cli-v1.0.0-aarch64-apple-darwin.tar.gz
abyss-cli-v1.0.0-x86_64-unknown-linux-musl.tar.gz
abyss-cli-v1.0.0-aarch64-apple-darwin-no-local.tar.gz
abyss-cli-v1.0.0-x86_64-unknown-linux-musl-no-local.tar.gz
abyss-runtime-v1.0.0-x86_64-pc-windows-msvc.zip
```

The default CLI archives keep their existing names and contain `abyss`,
`abyss-broker`, `abyss-delivery-plugin`, `abyss-broker@.service`, `VERSION`,
`LICENSE`, and `endpoint-artifact.json`. The public installer continues to select
these archives, with the `local` feature enabled. Deployment configuration,
backend, and dashboard are prepared separately by `abyss deploy-local`.

The `-no-local` archives have the same layout, but their CLI is built with
`--no-default-features`: `abyss deploy-local` is absent. They reuse the exact
broker and delivery plugin executables from the default archive for that target.
Downstream products can select this variant and add their own configuration;
the public installer does not select it.

The Windows runtime ZIP contains `abyss-broker.exe`,
`abyss-delivery-plugin.exe`, `abyss_callout_abi.h`, `VERSION`, `LICENSE`, and
`endpoint-artifact.json`. It does not include a CLI, driver, or native installer.
Host packagers provide the driver and product configuration, compare the bundled
ABI header with their driver's header, and sign staged copies of the executables
with their product certificate. The bundled header uses canonical LF line endings;
normalize a CRLF source checkout before comparing its hash.

Every archive's `endpoint-artifact.json` records schema version 1, repository,
full source `revision`, endpoint `version`, Rust `target`, `variant`
(`default`, `no-local`, or `runtime`), package `features`, and a `files` map from
payload filename to SHA-256. The map excludes the metadata file itself; the
release's `SHA256SUMS` covers all five complete archives. The workflow smoke-tests
the actual CLI command availability before accepting its declared feature set.
Downstream builds should pin the release, source revision, and archive digest,
then verify the archive before product signing changes its executable bytes.
The Git tag identifies the corresponding source available from GitHub's source
archive. The binaries remain covered by this repository's GPL license.

## Build and publish

`.github/workflows/cli-release.yml` builds both Unix CLI variants and the Windows
runtime, plus a standalone `abyss-query` archive for each of those three targets.
It exercises the download installer on Unix, runs the real archived
executables on their native runners, and verifies that `deploy-local` is present
only in the default CLI. Query archives also run `--help`, `--version`, and `schema`
on their native runners. A separate assembly job requires all five endpoint
archives with matching source revisions and versions, verifies payload and archive checksums,
and checks that CLI variants share identical broker and delivery binaries. Query
assembly independently requires all three targets with matching versions and
source revisions, and verifies payload and archive checksums.
Pull requests and manual dispatches validate the complete release and upload
Actions artifacts without publishing a GitHub Release. The installer smoke test
uses local release assets as the download transport.

1. Update the workspace version and dependencies as described in the
   [crates.io release guide](crates-io-release.md). CLI packaging rejects a tag
   that differs from the workspace version and only accepts stable versions.
2. Run `make test-install-cli` and merge the tested change into `main`.
   Run the endpoint release workflow manually to rehearse all three native builds.
3. Create and push the matching `v<version>` tag from the intended release
   commit. This also triggers the existing crates.io publication workflow;
   ensure its registry token and release prerequisites are ready.
4. The staging job waits for the assembled release, verifies its checksums,
   creates a draft GitHub Release, and uploads every GitHub asset. The final job
   checks that no newer stable release has been published, then publishes the
   GitHub Release as latest. Its `GITHUB_TOKEN` needs `contents: write`.
   Windows executables are published without product signing; no signing
   certificate or hardware token is needed here.

A failed upload leaves the release as a draft, allowing the original workflow
run to be retried. Published releases are never overwritten by the workflow;
source changes require a new version and tag. Tag workflows share one concurrency
lock across build, upload, and publication. Push release tags in version order
and wait for each release to finish before starting another version.

## Standalone component artifacts

The workflow retains three-platform standalone archives as Actions artifacts:

| Actions artifact | Contents |
| --- | --- |
| `broker-release` | Three `abyss-broker-v<version>-<target>` archives and `SHA256SUMS` |
| `abyss-query-release` | Three `abyss-query-v<version>-<target>` archives and `SHA256SUMS` |

Unix targets use `.tar.gz`; Windows uses `.zip`. Broker archives are derived from
verified endpoint archives and reuse the native-tested broker bytes. Query
archives are built and smoke-tested independently. Each standalone archive contains
its executable, `LICENSE`, `VERSION`, and `broker-artifact.json` or
`query-artifact.json`. Metadata records the repository, source revision, version,
target, and payload SHA-256 digests. Packaging is reproducible for identical inputs.
These artifacts remain available from the workflow run; the seven endpoint
GitHub Release assets listed above retain their existing contents.

## Local verification

Run `make test-install-cli` for installer, packaging, assembly, and latest-release
promotion checks. `test_release_artifacts.py` covers broker packaging, provenance,
reproducibility, corrupted inputs, missing platforms, and protection against
promoting an older published version. `test_release_query.py` covers standalone
query packaging and the complete three-platform assembly boundary.

For a local packaging rehearsal after compiling the three release binaries:

```sh
python3 scripts/ci/package_cli.py --target aarch64-apple-darwin \
  --binaries target/aarch64-apple-darwin/release --output /tmp/abyss-cli-release
cat /tmp/abyss-cli-release/SHA256SUMS.* > /tmp/abyss-cli-release/SHA256SUMS
sh scripts/tests/smoke_release_install.sh /tmp/abyss-cli-release
```

Use `x86_64-unknown-linux-musl` on Linux, with the Rust target and `musl-gcc`
installed. After archiving the default CLI, build only `abyss-cli` again with
`--no-default-features`, then rerun packaging with `--variant no-local`. Package
both variants before changing or cleaning their input binaries:

```sh
cargo build --release --locked --target aarch64-apple-darwin \
  -p abyss-cli --no-default-features
python3 scripts/ci/package_cli.py --target aarch64-apple-darwin \
  --binaries target/aarch64-apple-darwin/release \
  --output /tmp/abyss-cli-release --variant no-local
python3 scripts/ci/verify_release.py --smoke /tmp/abyss-cli-release/*.tar.gz
```

On Windows, build only `abyss-broker` and `abyss-delivery-plugin` for
`x86_64-pc-windows-msvc`, then pass that target and `--variant runtime` to the
packager. Run `verify_release.py --smoke` on the resulting ZIP on Windows.
Packaging requires Python 3.9+, Cargo, and Git but performs no compilation.

Run `python3 scripts/tests/test_release_artifacts.py` for portable package and
assembly regression tests, including Windows ZIP contents, variant separation,
missing platforms, mixed revisions, corrupted payloads, and invalid checksums.
