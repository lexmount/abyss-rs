#!/usr/bin/env python3
"""Upload component releases and promote version-pinned Tencent CDN manifests."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path

from package_broker import broker_archive_name
from package_cli import TARGETS
from package_query import query_archive_name

COMPONENTS = {
    "broker": ("broker", broker_archive_name),
    "abyss-query": ("tools/abyss-query", query_archive_name),
}


def stable_version(tag: str) -> tuple[int, ...]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("CDN publication requires a stable v<version> tag")
    return tuple(int(part) for part in tag[1:].split("."))


def release_files(source: Path, tag: str, component: str = "broker") -> list[Path]:
    stable_version(tag)
    _, archive_name = COMPONENTS[component]
    names = sorted(archive_name(tag, target) for target in TARGETS)
    if {path.name for path in source.iterdir()} != {*names, "SHA256SUMS"}:
        raise ValueError(
            f"{component} CDN release must contain exactly three archives and SHA256SUMS"
        )
    files = [source / name for name in [*names, "SHA256SUMS"]]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("CDN assets must be regular files, not symlinks")
    checksums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in files[:-1]
    )
    if files[-1].read_text() != checksums:
        raise ValueError(f"{component} release SHA-256 mismatch")
    return files


def check_promotion(tag: str, published_tags: list[str] | None) -> None:
    """Prevent a delayed tag run from replacing a newer published release."""
    version = stable_version(tag)
    if published_tags is None:
        raise ValueError("latest promotion requires the published stable release tags")
    for published in published_tags:
        if re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", published):
            if stable_version(published) > version:
                raise ValueError(f"refusing to promote {tag}: {published} is published")


def latest_manifest(files: list[Path], tag: str, component: str = "broker") -> dict:
    """Pin all platform paths and archive digests in one replaceable object."""
    archives = {path.name: path for path in files[:-1]}
    prefix, archive_name = COMPONENTS[component]
    artifacts = {}
    for target in sorted(TARGETS):
        name = archive_name(tag, target)
        archive = archives[name]
        artifacts[target] = {
            "path": f"/{prefix}/{tag}/{name}",
            "sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "size": archive.stat().st_size,
        }
    return {
        "schema_version": 1,
        "version": tag[1:],
        "tag": tag,
        "artifacts": artifacts,
    }


def publish(
    source: Path,
    tag: str,
    bucket: str,
    region: str,
    coscli: Path,
    *,
    component: str = "broker",
    latest_only: bool = False,
    published_tags: list[str] | None = None,
) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*-[0-9]+", bucket):
        raise ValueError("TENCENT_COS_BUCKET must include the COS APPID suffix")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", region):
        raise ValueError("TENCENT_COS_REGION is required and must be a COS region")
    files = release_files(source, tag, component)
    prefix, _ = COMPONENTS[component]
    if latest_only:
        check_promotion(tag, published_tags)
    credentials = {}
    for name in ("TENCENTCLOUD_SECRET_ID", "TENCENTCLOUD_SECRET_KEY"):
        if not os.environ.get(name):
            raise ValueError(f"{name} is required")
        credentials[name] = os.environ[name]
    child_env = {
        key: value for key, value in os.environ.items() if key not in credentials
    }
    # COSCLI accepts JSON as YAML. Keep credentials out of argv and remove the
    # private temporary config on success and failure, following AbyssApp's uploader.
    with tempfile.TemporaryDirectory(
        prefix=f"abyss-{component}-cos-", dir=os.environ.get("RUNNER_TEMP")
    ) as temporary:
        config = Path(temporary) / "credentials.yaml"
        with open(
            config,
            "x",
            encoding="utf-8",
            opener=lambda path, flags: os.open(path, flags, 0o600),
        ) as stream:
            json.dump(
                {
                    "cos": {
                        "base": {
                            "secretid": credentials["TENCENTCLOUD_SECRET_ID"],
                            "secretkey": credentials["TENCENTCLOUD_SECRET_KEY"],
                            "sessiontoken": "",
                            "protocol": "https",
                            "mode": "SecretKey",
                            "disableencryption": "true",
                            "disableautofetchbuckettype": "true",
                        },
                        "buckets": [],
                    }
                },
                stream,
            )
        # Versioned uploads finish with SHA256SUMS. Promotion is a separate job
        # gated on BOTH origins, and changes only a single small JSON object.
        uploads = [(asset, f"{prefix}/{tag}/{asset.name}", []) for asset in files]
        if latest_only:
            manifest = Path(temporary) / "manifest.json"
            manifest.write_text(
                json.dumps(
                    latest_manifest(files, tag, component), indent=2, sort_keys=True
                )
                + "\n",
                encoding="utf-8",
            )
            uploads = [
                (
                    manifest,
                    f"{prefix}/latest/manifest.json",
                    [
                        "--meta",
                        "Content-Type:application/json; charset=utf-8#"
                        "Cache-Control:no-cache, no-store, max-age=0, must-revalidate",
                    ],
                )
            ]
        for asset, key, metadata in uploads:
            destination = f"cos://{bucket}/{key}"
            subprocess.run(
                [
                    str(coscli),
                    "cp",
                    str(asset),
                    destination,
                    "--config-path",
                    str(config),
                    "--endpoint",
                    f"cos.{region}.myqcloud.com",
                    "--bucket-type",
                    "COS",
                    "--disable-log=true",
                    "--process-log=false",
                    "--fail-output=false",
                    *metadata,
                ],
                env=child_env,
                check=True,
            )
            print(f"Uploaded {asset.name} to {destination}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", choices=COMPONENTS, default="broker")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--coscli", type=Path, required=True)
    parser.add_argument(
        "--latest-only",
        action="store_true",
        help="promote the manifest only, after both versioned origins are complete",
    )
    parser.add_argument(
        "--published-tags",
        type=Path,
        help="all published stable release tags, one per line; required for promotion",
    )
    args = parser.parse_args()
    if args.latest_only and args.published_tags is None:
        parser.error("--latest-only requires --published-tags")
    publish(
        args.source,
        args.tag,
        os.environ.get("TENCENT_COS_BUCKET", ""),
        os.environ.get("TENCENT_COS_REGION", ""),
        args.coscli,
        component=args.component,
        latest_only=args.latest_only,
        published_tags=(
            args.published_tags.read_text().splitlines()
            if args.published_tags is not None
            else None
        ),
    )


if __name__ == "__main__":
    main()
