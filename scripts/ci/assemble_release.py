#!/usr/bin/env python3
"""Assemble a complete, same-revision endpoint release before publication."""

from __future__ import annotations

import argparse
import hashlib
import shutil
from pathlib import Path

from package_cli import TARGETS, WINDOWS_TARGET
from verify_release import read_artifact


def assemble(artifacts: Path, output: Path, revision: str) -> None:
    expected = {
        (target, variant)
        for target in TARGETS
        for variant in (
            ("runtime",) if target == WINDOWS_TARGET else ("default", "no-local")
        )
    }
    archives = sorted([*artifacts.rglob("*.tar.gz"), *artifacts.rglob("*.zip")])
    seen = set()
    versions = set()
    runtimes = {}
    for archive in archives:
        metadata, _ = read_artifact(archive)
        identity = metadata["target"], metadata["variant"]
        if identity in seen or identity not in expected:
            raise ValueError("duplicate or unexpected endpoint artifact")
        seen.add(identity)
        versions.add(metadata["version"])
        if metadata["revision"] != revision:
            raise ValueError("endpoint artifact was built from a different revision")
        if identity[0] != WINDOWS_TARGET:
            runtime = {
                name: metadata["files"][name]
                for name in ("abyss-broker", "abyss-delivery-plugin")
            }
            if identity[0] in runtimes and runtimes[identity[0]] != runtime:
                raise ValueError(
                    "CLI variants must share identical broker and delivery binaries"
                )
            runtimes[identity[0]] = runtime
        checksum_suffix = "" if identity[1] == "default" else f".{identity[1]}"
        checksum_file = archive.parent / f"SHA256SUMS.{identity[0]}{checksum_suffix}"
        checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
        if checksum_file.read_text() != f"{checksum}  {archive.name}\n":
            raise ValueError("release archive SHA-256 mismatch")
    if seen != expected or len(versions) != 1:
        raise ValueError("release requires all five artifacts with the same version")
    installers = sorted(artifacts.rglob("install.sh"))
    if len(installers) != 2 or installers[0].read_bytes() != installers[1].read_bytes():
        raise ValueError("release requires identical Linux and macOS installers")
    installer = installers[0].read_bytes()
    version = next(iter(versions))
    if f"version='{version}'".encode() not in installer:
        raise ValueError("installer version does not match the release")
    if output.exists() and any(output.iterdir()):
        raise ValueError("release output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    checksums = []
    for source in archives:
        shutil.copyfile(source, output / source.name)
        checksums.append(
            f"{hashlib.sha256(source.read_bytes()).hexdigest()}  {source.name}\n"
        )
    (output / "install.sh").write_bytes(installer)
    (output / "SHA256SUMS").write_text("".join(checksums))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--revision", required=True)
    args = parser.parse_args()
    assemble(args.artifacts, args.output, args.revision)
    print(f"Assembled complete endpoint release in {args.output}")


if __name__ == "__main__":
    main()
