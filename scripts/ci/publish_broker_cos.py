#!/usr/bin/env python3
"""Upload a complete broker release to a deployment-configured Tencent COS origin."""

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


def release_files(source: Path, tag: str) -> list[Path]:
    if not re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+", tag):
        raise ValueError("broker CDN publication requires a stable v<version> tag")
    names = sorted(broker_archive_name(tag, target) for target in TARGETS)
    if {path.name for path in source.iterdir()} != {*names, "SHA256SUMS"}:
        raise ValueError(
            "broker CDN release must contain exactly three archives and SHA256SUMS"
        )
    files = [source / name for name in [*names, "SHA256SUMS"]]
    if any(path.is_symlink() or not path.is_file() for path in files):
        raise ValueError("broker CDN assets must be regular files, not symlinks")
    checksums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in files[:-1]
    )
    if files[-1].read_text() != checksums:
        raise ValueError("broker release SHA-256 mismatch")
    return files


def publish(source: Path, tag: str, bucket: str, region: str, coscli: Path) -> None:
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*-[0-9]+", bucket):
        raise ValueError("TENCENT_COS_BUCKET must include the COS APPID suffix")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", region):
        raise ValueError("TENCENT_COS_REGION is required and must be a COS region")
    files = release_files(source, tag)
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
        prefix="abyss-broker-cos-", dir=os.environ.get("RUNNER_TEMP")
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
        # SHA256SUMS is the completion marker and is always uploaded last.
        for asset in files:
            destination = f"cos://{bucket}/broker/{tag}/{asset.name}"
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
                ],
                env=child_env,
                check=True,
            )
            print(f"Uploaded {asset.name} to {destination}", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--coscli", type=Path, required=True)
    args = parser.parse_args()
    publish(
        args.source,
        args.tag,
        os.environ.get("TENCENT_COS_BUCKET", ""),
        os.environ.get("TENCENT_COS_REGION", ""),
        args.coscli,
    )


if __name__ == "__main__":
    main()
