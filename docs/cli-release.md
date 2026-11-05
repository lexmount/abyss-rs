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
runtime. It exercises the download installer on Unix, runs the real archived
executables on their native runners, and verifies that `deploy-local` is present
only in the default CLI. A separate assembly job requires all five archives with
matching source revisions and versions, verifies payload and archive checksums,
and checks that CLI variants share identical broker and delivery binaries.
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
4. The publication job waits for the assembled release, verifies its checksums,
   creates a draft GitHub Release, and uploads every GitHub asset. Both CN and COM
   broker CDN uploads must then succeed. A final job promotes both latest manifests
   before publishing the GitHub Release as latest.
   Its `GITHUB_TOKEN` needs `contents: write`; the CDN credentials and repository
   variables below must also be configured. Windows executables are published without
   product signing; no signing certificate or hardware token is needed here.

A failed upload leaves the release as a draft, allowing the original workflow
run to be retried. Published releases are never overwritten by the workflow;
source changes require a new version and tag. Tag workflows share one concurrency
lock across build, upload, promotion, and publication. Push release tags in version
order and wait for each release to finish before starting another version.

## Broker CDN publication

The same tag workflow derives three broker-only archives from the verified
endpoint release. It reuses the native-tested broker bytes; it does not rebuild
or sign them. Each archive contains `abyss-broker` (or `abyss-broker.exe`),
`LICENSE`, `VERSION`, and `broker-artifact.json`. The metadata records the public
source repository, full commit revision, version, target, and payload SHA-256
digests. Archive output is reproducible for the same input release.

Both deployment-configured Tencent COS buckets receive this layout:

```text
broker/v1.0.0/
  abyss-broker-v1.0.0-aarch64-apple-darwin.tar.gz
  abyss-broker-v1.0.0-x86_64-unknown-linux-musl.tar.gz
  abyss-broker-v1.0.0-x86_64-pc-windows-msvc.zip
  SHA256SUMS
broker/latest/
  manifest.json
```

The existing CDN domains must use those buckets as their origins and preserve
the object path. Downloads then use `<CDN base URL>/broker/v<version>/<filename>`.
Archive paths remain versioned. `broker/latest/manifest.json` is the fixed discovery
URL for automatic downloads; it points to those archives instead of uploading
another copy of every binary. The existing seven GitHub Release assets are unchanged.

### Download the latest broker

Fetch `<CDN base URL>/broker/latest/manifest.json`. Schema version 1 contains:

| Field | Meaning |
| --- | --- |
| `schema_version` | `1` |
| `version` | Stable version, such as `1.0.0` |
| `tag` | Corresponding release tag, such as `v1.0.0` |
| `artifacts` | Map keyed by `aarch64-apple-darwin`, `x86_64-unknown-linux-musl`, and `x86_64-pc-windows-msvc` |
| `artifacts[target].path` | Root-relative path on the same CDN host, such as `/broker/v1.0.0/abyss-broker-v1.0.0-x86_64-unknown-linux-musl.tar.gz` |
| `artifacts[target].sha256` | SHA-256 of the complete archive |
| `artifacts[target].size` | Archive size in bytes |

Read the manifest once per update, select the target, resolve `path` against the
manifest URL, and verify both size and SHA-256 before unpacking. Keep the same
manifest snapshot for the whole download. Even if a new release appears during
the transfer, that snapshot pins the archive and digest to one version.

For example, this downloads a Linux archive using Python 3 (replace the example
CDN host with your deployment's domain):

```sh
python3 - 'https://downloads.example.com/broker/latest/manifest.json' \
  x86_64-unknown-linux-musl <<'PY'
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import urljoin
from urllib.request import urlopen

manifest_url, target = sys.argv[1:]
with urlopen(manifest_url, timeout=30) as response:
    manifest = json.load(response)
if manifest['schema_version'] != 1:
    raise SystemExit('Unsupported broker manifest schema')
asset = manifest['artifacts'][target]
if not asset['path'].startswith(f"/broker/{manifest['tag']}/"):
    raise SystemExit('Unexpected broker archive path')
with urlopen(urljoin(manifest_url, asset['path']), timeout=120) as response:
    archive = response.read()
if (len(archive) != asset['size']
        or hashlib.sha256(archive).hexdigest() != asset['sha256']):
    raise SystemExit('Broker archive checksum or size mismatch')
destination = Path(asset['path']).name
Path(destination).write_bytes(archive)
print(destination)
PY
```

### Latest publication and caching

Versioned uploads finish with `SHA256SUMS`. Only after **both CN and COM** upload
jobs succeed does the final job replace each origin's latest manifest with one
object upload. A client sees a complete old or new manifest, and both reference
complete versioned artifacts. There is no transaction across the two origins:
if promotion fails midway, they may temporarily advertise different complete
versions. Retry the failed final job to finish promotion and publish the GitHub
Release; it does not re-upload the binary archives.

The final job fetches all published, non-prerelease GitHub release tags and rejects
promotion when a newer stable version already exists. This prevents a delayed old
tag run from rolling back an already published release's latest entry. Repeating
the same version produces the same manifest bytes.

The manifest is uploaded with `Content-Type: application/json; charset=utf-8` and
`Cache-Control: no-cache, no-store, max-age=0, must-revalidate`. Configure **both CDN
domains** so `/broker/latest/manifest.json` follows the origin's cache headers or
has a highest-priority **do not cache** rule. Forced edge caching or a browser
cache rule must not override this header. Tencent's
[cache rule documentation](https://cloud.tencent.com/document/product/228/47672)
explains that forced caching can override `no-store`. Versioned archive paths can
retain normal long-lived caching. The workflow does not need CDN purge credentials.

For manual recovery, first verify that both origins have the complete versioned
release. Fetch the published tag list and run the following promotion command
once for each origin with its bucket/region environment variables configured:

```sh
gh api --paginate 'repos/lexmount/abyss-rs/releases?per_page=100' \
  --jq '.[] | select(.draft == false and .prerelease == false) | .tag_name' \
  > published-tags.txt
python3 scripts/ci/publish_broker_cos.py --source broker-dist \
  --tag v1.0.0 --coscli /path/to/coscli \
  --latest-only --published-tags published-tags.txt
```

Use the actual release tag and original `broker-release` Actions artifact. Keep
manual recovery serialized with tag workflows. For a newly introduced discovery
URL, an operator can promote the current published release without rebuilding it.

### Credentials and verification

Under **Settings → Secrets and variables → Actions**, configure these repository
secrets (or allow this repository to use equivalent organization secrets):

| Secret | Value |
| --- | --- |
| `TENCENTCLOUD_SECRET_ID` | Tencent Cloud CAM credential SecretId, as used by AbyssApp |
| `TENCENTCLOUD_SECRET_KEY` | Matching SecretKey |

Configure these non-secret repository **Variables** for the two CDN origins:

| Variable | Value |
| --- | --- |
| `TENCENT_COS_CN_BUCKET` | CN bucket name including its numeric APPID suffix |
| `TENCENT_COS_CN_REGION` | CN bucket region, for example `ap-nanjing` |
| `TENCENT_COS_COM_BUCKET` | COM bucket name including its numeric APPID suffix |
| `TENCENT_COS_COM_REGION` | COM bucket region, for example `ap-hongkong` |

The credentials must permit COSCLI uploads to `broker/*` (including
`broker/latest/manifest.json`) in both buckets,
including multipart uploads. Tencent's [COSCLI cp documentation](https://cloud.tencent.com/document/product/436/63669)
lists the required bucket checks and object/multipart actions: `HeadBucket`,
`GetBucket`, `HeadObject`, `InitiateMultipartUpload`, `UploadPart`,
`CompleteMultipartUpload`, `ListMultipartUploads`, `ListParts`, `PutObject`, and
`AbortMultipartUpload`. Restrict object permissions to `broker/*`; bucket-level
checks apply to the selected buckets. Credentials already scoped only to
AbyssApp's `releases/*` or `skills/*` need the additional broker prefix.
No CDN-management credentials or product-signing secrets are used.

The workflow pins the COSCLI download SHA-256, matching AbyssApp's verified
uploader. Credentials are written to a private temporary config, excluded from
command arguments and the COSCLI child environment, and removed on exit. The
publisher verifies the complete three-platform checksum set before uploading and
uploads `SHA256SUMS` last. An upload failure fails that site's job and keeps the
GitHub Release in draft. Re-run failed jobs from the original tag run after fixing
configuration or connectivity; successful matrix jobs need not be repeated.
PR and manual workflow runs only build and validate Actions artifacts.

Run `python3 scripts/tests/test_release_broker_cos.py` for offline publisher
tests, including manifest paths and hashes, cache metadata, idempotent promotion,
failure cleanup, and protection against promoting an older published version.
`test_release_artifacts.py` also checks broker packaging, provenance,
reproducibility, corrupted inputs, and missing platforms.

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
