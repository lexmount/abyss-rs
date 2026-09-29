#!/usr/bin/env python3
"""Package endpoint binaries for public CLI and downstream Host distributions."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WINDOWS_TARGET = "x86_64-pc-windows-msvc"
TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-musl", WINDOWS_TARGET)
VARIANTS = ("default", "no-local", "runtime")
BINARIES = ("abyss", "abyss-broker", "abyss-delivery-plugin")
METADATA_FILE = "endpoint-artifact.json"
ABI_HEADER = "abyss_callout_abi.h"


def package(
    target: str, binaries: Path, output: Path, tag: str | None, variant: str = "default"
) -> Path:
    if target not in TARGETS or variant not in VARIANTS:
        raise ValueError("unsupported release target or variant")
    if (target == WINDOWS_TARGET) != (variant == "runtime"):
        raise ValueError(
            "Windows supports only the runtime variant; CLI variants require Unix"
        )
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
    names = BINARIES[1:] if variant == "runtime" else ("abyss-cli", *BINARIES[1:])
    versions = {
        name: next(
            item["version"] for item in metadata["packages"] if item["name"] == name
        )
        for name in names
    }
    if len(set(versions.values())) != 1:
        raise ValueError("endpoint binary package versions must match")
    version = next(iter(versions.values()))
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("endpoint releases require a stable workspace version")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} does not match workspace version v{version}")
    suffix = ".exe" if target == WINDOWS_TARGET else ""
    binary_names = tuple(
        name + suffix for name in (BINARIES[1:] if variant == "runtime" else BINARIES)
    )
    files = {name: (binaries / name).read_bytes() for name in binary_names}
    if any(not content for content in files.values()):
        raise ValueError("release binaries must not be empty")
    files.update(
        {
            "LICENSE": (ROOT / "LICENSE").read_bytes(),
            "VERSION": f"{version}\n".encode(),
        }
    )
    if variant == "runtime":
        # Use canonical LF text regardless of the Windows checkout's autocrlf.
        files[ABI_HEADER] = (
            (ROOT / "crates/abyss-broker/include" / ABI_HEADER)
            .read_text(encoding="utf-8")
            .encode("utf-8")
        )
    else:
        # Keep the existing public archive contract, including this file on macOS.
        files["abyss-broker@.service"] = (
            ROOT / "platform/linux/abyss-broker@.service"
        ).read_bytes()
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    features = {"abyss-broker": [], "abyss-delivery-plugin": []}
    if variant != "runtime":
        features["abyss-cli"] = ["local"] if variant == "default" else []
    files[METADATA_FILE] = (
        json.dumps(
            {
                "schema_version": 1,
                "repository": "https://github.com/lexmount/abyss-rs",
                "revision": revision,
                "version": version,
                "target": target,
                "variant": variant,
                "features": features,
                "files": {
                    name: hashlib.sha256(content).hexdigest()
                    for name, content in files.items()
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    output.mkdir(parents=True, exist_ok=True)
    if variant == "runtime":
        archive = output / f"abyss-runtime-v{version}-{target}.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            for name, content in files.items():
                bundle.writestr(name, content)
    else:
        variant_suffix = "-no-local" if variant == "no-local" else ""
        archive = output / f"abyss-cli-v{version}-{target}{variant_suffix}.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o755 if name in binary_names else 0o644
                bundle.addfile(info, io.BytesIO(content))
    if variant == "default":
        installer = (ROOT / "scripts/install.sh").read_text()
        if installer.count("@ABYSS_VERSION@") != 1:
            raise ValueError("installer must have exactly one version marker")
        (output / "install.sh").write_text(
            installer.replace("@ABYSS_VERSION@", version)
        )
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum_suffix = "" if variant == "default" else f".{variant}"
    (output / f"SHA256SUMS.{target}{checksum_suffix}").write_text(
        f"{checksum}  {archive.name}\n"
    )
    return archive


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=TARGETS)
    parser.add_argument("--binaries", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--variant", choices=VARIANTS, default="default")
    args = parser.parse_args()
    print(package(args.target, args.binaries, args.output, args.tag, args.variant))


if __name__ == "__main__":
    main()
