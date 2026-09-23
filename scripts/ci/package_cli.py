#!/usr/bin/env python3
"""Package the public CLI runtime and stamp its release download installer."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-musl")
BINARIES = ("abyss", "abyss-broker", "abyss-delivery-plugin")


def package(target: str, binaries: Path, output: Path, tag: str | None) -> Path:
    metadata = json.loads(
        subprocess.check_output(
            [
                "cargo",
                "metadata",
                "--format-version",
                "1",
                "--no-deps",
                "--offline",
                "--locked",
            ],
            cwd=ROOT,
            text=True,
        )
    )
    version = next(
        package["version"]
        for package in metadata["packages"]
        if package["name"] == "abyss-cli"
    )
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("CLI releases require a stable workspace version")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} does not match workspace version v{version}")
    files = {name: (binaries / name).read_bytes() for name in BINARIES}
    files.update(
        {
            "abyss-broker@.service": (
                ROOT / "platform/linux/abyss-broker@.service"
            ).read_bytes(),
            "LICENSE": (ROOT / "LICENSE").read_bytes(),
            "VERSION": f"{version}\n".encode(),
        }
    )
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"abyss-cli-v{version}-{target}.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name, content in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o755 if name in BINARIES else 0o644
            bundle.addfile(info, io.BytesIO(content))
    installer = (ROOT / "scripts/install.sh").read_text()
    if installer.count("@ABYSS_VERSION@") != 1:
        raise ValueError("installer must have exactly one version marker")
    (output / "install.sh").write_text(installer.replace("@ABYSS_VERSION@", version))
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / f"SHA256SUMS.{target}").write_text(f"{checksum}  {archive.name}\n")
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tag")
    args = parser.parse_args()
    print(package(args.target, args.binaries, args.output, args.tag))


if __name__ == "__main__":
    main()
