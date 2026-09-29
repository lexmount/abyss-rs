#!/usr/bin/env python3
"""Validate endpoint archives and optionally run their native executables."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

from package_cli import ABI_HEADER, BINARIES, METADATA_FILE, TARGETS, WINDOWS_TARGET


def read_artifact(archive: Path) -> tuple[dict, dict[str, bytes]]:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            names = bundle.namelist()
            files = {name: bundle.read(name) for name in names}
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if any(not member.isfile() for member in members):
                raise ValueError("release archive must contain only regular files")
            names = [member.name for member in members]
            files = {
                member.name: bundle.extractfile(member).read() for member in members
            }
    if len(names) != len(set(names)):
        raise ValueError("duplicate release archive member")
    metadata = json.loads(files.pop(METADATA_FILE))
    target, variant = metadata["target"], metadata["variant"]
    if metadata["schema_version"] != 1 or target not in TARGETS:
        raise ValueError("unsupported endpoint artifact schema or target")
    if metadata["repository"] != "https://github.com/lexmount/abyss-rs":
        raise ValueError("unexpected endpoint repository")
    if not re.fullmatch(r"[0-9a-f]{40}", metadata["revision"]):
        raise ValueError("endpoint revision must be a full Git commit SHA")
    version = metadata["version"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("endpoint version must be a stable version")
    features = {"abyss-broker": [], "abyss-delivery-plugin": []}
    if target == WINDOWS_TARGET:
        if variant != "runtime":
            raise ValueError("Windows requires a runtime artifact")
        expected = {name + ".exe" for name in BINARIES[1:]} | {ABI_HEADER}
        archive_name = f"abyss-runtime-v{version}-{target}.zip"
    else:
        if variant not in ("default", "no-local"):
            raise ValueError("Unix requires a CLI artifact")
        expected = set(BINARIES) | {"abyss-broker@.service"}
        features["abyss-cli"] = ["local"] if variant == "default" else []
        suffix = "-no-local" if variant == "no-local" else ""
        archive_name = f"abyss-cli-v{version}-{target}{suffix}.tar.gz"
    if archive.name != archive_name or metadata["features"] != features:
        raise ValueError(
            "artifact name or features do not match its target and variant"
        )
    if files.keys() != expected | {"LICENSE", "VERSION"}:
        raise ValueError("unexpected release archive contents")
    if metadata["files"] != {
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()
    }:
        raise ValueError("release payload SHA-256 mismatch")
    if (
        any(not data for data in files.values())
        or files["VERSION"] != f"{version}\n".encode()
    ):
        raise ValueError("empty payload or incorrect VERSION")
    return metadata, files


def smoke(archive: Path) -> None:
    metadata, files = read_artifact(archive)
    windows = metadata["target"] == WINDOWS_TARGET
    names = tuple(name + ".exe" for name in BINARIES[1:]) if windows else BINARIES
    with tempfile.TemporaryDirectory(prefix="abyss-artifact-smoke-") as directory:
        root = Path(directory)
        for name in names:
            executable = root / name
            executable.write_bytes(files[name])
            executable.chmod(0o755)
            subprocess.run([str(executable), "--help"], check=True, capture_output=True)
        if not windows:
            cli = str(root / "abyss")
            version = subprocess.check_output([cli, "version"], text=True).strip()
            if version != metadata["version"]:
                raise ValueError("CLI executable version does not match the artifact")
            result = subprocess.run(
                [cli, "deploy-local", "--help"], capture_output=True, text=True
            )
            if metadata["variant"] == "default":
                if result.returncode != 0 or "start" not in result.stdout:
                    raise ValueError("default CLI must include deploy-local")
            elif (
                result.returncode != 2 or "unrecognized subcommand" not in result.stderr
            ):
                raise ValueError("no-local CLI must reject deploy-local")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    for archive in args.archives:
        if args.smoke:
            smoke(archive)
        else:
            read_artifact(archive)
        print(f"Verified {archive.name}")


if __name__ == "__main__":
    main()
