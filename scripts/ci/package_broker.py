#!/usr/bin/env python3
"""Derive reproducible broker-only CDN archives from a verified endpoint release."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import tarfile
import zipfile
from pathlib import Path

from package_cli import TARGETS, WINDOWS_TARGET
from verify_release import read_artifact


def broker_archive_name(tag: str, target: str) -> str:
    suffix = "zip" if target == WINDOWS_TARGET else "tar.gz"
    return f"abyss-broker-{tag}-{target}.{suffix}"


def package_brokers(release: Path, output: Path, revision: str) -> None:
    archives = sorted([*release.glob("*.tar.gz"), *release.glob("*.zip")])
    # Validate the complete input checksum list before deriving any CDN assets.
    checksums = "".join(
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
        for path in archives
    )
    if not archives or sorted(
        (release / "SHA256SUMS").read_text().splitlines()
    ) != sorted(checksums.splitlines()):
        raise ValueError("endpoint release SHA-256 mismatch")
    selected = {}
    versions = set()
    for archive in archives:
        metadata, files = read_artifact(archive)
        if metadata["revision"] != revision:
            raise ValueError("endpoint artifact was built from a different revision")
        versions.add(metadata["version"])
        if metadata["variant"] == "no-local":
            continue
        target = metadata["target"]
        if target in selected:
            raise ValueError("duplicate broker target")
        executable = "abyss-broker.exe" if target == WINDOWS_TARGET else "abyss-broker"
        payload = {name: files[name] for name in (executable, "LICENSE", "VERSION")}
        payload["broker-artifact.json"] = (
            json.dumps(
                {
                    "schema_version": 1,
                    "repository": metadata["repository"],
                    "revision": revision,
                    "version": metadata["version"],
                    "target": target,
                    "files": {
                        name: hashlib.sha256(data).hexdigest()
                        for name, data in payload.items()
                    },
                },
                indent=2,
                sort_keys=True,
            )
            + "\n"
        ).encode()
        selected[target] = payload
    if set(selected) != set(TARGETS) or len(versions) != 1:
        raise ValueError(
            "broker release requires all three targets with the same version"
        )
    if output.exists() and any(output.iterdir()):
        raise ValueError("broker output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    tag = f"v{next(iter(versions))}"
    for target, files in selected.items():
        archive = output / broker_archive_name(tag, target)
        if target == WINDOWS_TARGET:
            with zipfile.ZipFile(archive, "w") as bundle:
                for name, data in files.items():
                    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.create_system = 3
                    info.external_attr = 0o100644 << 16
                    bundle.writestr(info, data)
        else:
            with archive.open("wb") as raw:
                with gzip.GzipFile(
                    filename="", fileobj=raw, mode="wb", mtime=0
                ) as compressed:
                    with tarfile.open(fileobj=compressed, mode="w") as bundle:
                        for name, data in files.items():
                            info = tarfile.TarInfo(name)
                            info.size = len(data)
                            info.mode = 0o755 if name == "abyss-broker" else 0o644
                            bundle.addfile(info, io.BytesIO(data))
    (output / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(output.iterdir())
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    package_brokers(args.release, args.output, args.revision)
    print(f"Packaged broker CDN release in {args.output}")


if __name__ == "__main__":
    main()
