#!/usr/bin/env python3
"""Package, verify, and assemble standalone abyss-query releases."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

from package_cli import ROOT, TARGETS, WINDOWS_TARGET

METADATA_FILE = "query-artifact.json"
REPOSITORY = "https://github.com/lexmount/abyss-rs"


def query_archive_name(tag: str, target: str) -> str:
    suffix = "zip" if target == WINDOWS_TARGET else "tar.gz"
    return f"abyss-query-{tag}-{target}.{suffix}"


def package_query(target: str, binaries: Path, output: Path, tag: str | None) -> Path:
    if target not in TARGETS:
        raise ValueError("unsupported query release target")
    workspace = json.loads(
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
        item["version"]
        for item in workspace["packages"]
        if item["name"] == "abyss-query-cli"
    )
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("query releases require a stable workspace version")
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} does not match workspace version v{version}")
    executable = "abyss-query.exe" if target == WINDOWS_TARGET else "abyss-query"
    binary = binaries / executable
    if binary.is_symlink() or not binary.is_file():
        raise ValueError("query executable must be a regular file")
    files = {
        executable: binary.read_bytes(),
        "LICENSE": (ROOT / "LICENSE").read_bytes(),
        "VERSION": f"{version}\n".encode(),
    }
    if not files[executable]:
        raise ValueError("query executable must not be empty")
    revision = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()
    files[METADATA_FILE] = (
        json.dumps(
            {
                "schema_version": 1,
                "repository": REPOSITORY,
                "revision": revision,
                "version": version,
                "target": target,
                "files": {
                    name: hashlib.sha256(data).hexdigest()
                    for name, data in files.items()
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    output.mkdir(parents=True, exist_ok=True)
    archive = output / query_archive_name(f"v{version}", target)
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
                        info.mode = 0o755 if name == executable else 0o644
                        bundle.addfile(info, io.BytesIO(data))
    (output / f"SHA256SUMS.{target}").write_text(checksum_line(archive))
    return archive


def checksum_line(archive: Path) -> str:
    return f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"


def read_query_artifact(archive: Path) -> tuple[dict, dict[str, bytes]]:
    if archive.is_symlink() or not archive.is_file():
        raise ValueError("query archive must be a regular file")
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as bundle:
            members = bundle.infolist()
            if any(
                member.is_dir() or (member.external_attr >> 16) & 0o170000 != 0o100000
                for member in members
            ):
                raise ValueError("query archive must contain only regular files")
            names = bundle.namelist()
            files = {name: bundle.read(name) for name in names}
    else:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if any(not member.isfile() for member in members):
                raise ValueError("query archive must contain only regular files")
            names = [member.name for member in members]
            files = {
                member.name: bundle.extractfile(member).read() for member in members
            }
            for member in members:
                if member.name == "abyss-query" and member.mode != 0o755:
                    raise ValueError("query executable must have mode 0755")
    if len(names) != len(set(names)):
        raise ValueError("duplicate query archive member")
    metadata = json.loads(files.pop(METADATA_FILE))
    target, version = metadata["target"], metadata["version"]
    if metadata["schema_version"] != 1 or target not in TARGETS:
        raise ValueError("unsupported query artifact schema or target")
    if metadata["repository"] != REPOSITORY:
        raise ValueError("unexpected query repository")
    if not re.fullmatch(r"[0-9a-f]{40}", metadata["revision"]):
        raise ValueError("query revision must be a full Git commit SHA")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("query version must be a stable version")
    if archive.name != query_archive_name(f"v{version}", target):
        raise ValueError("query artifact name does not match its target and version")
    executable = "abyss-query.exe" if target == WINDOWS_TARGET else "abyss-query"
    if files.keys() != {executable, "LICENSE", "VERSION"}:
        raise ValueError("unexpected query archive contents")
    if metadata["files"] != {
        name: hashlib.sha256(data).hexdigest() for name, data in files.items()
    }:
        raise ValueError("query payload SHA-256 mismatch")
    if (
        any(not data for data in files.values())
        or files["VERSION"] != f"{version}\n".encode()
    ):
        raise ValueError("empty query payload or incorrect VERSION")
    return metadata, files


def assemble_queries(artifacts: Path, output: Path, revision: str) -> None:
    archives = sorted([*artifacts.rglob("*.tar.gz"), *artifacts.rglob("*.zip")])
    targets, versions = set(), set()
    for archive in archives:
        metadata, _ = read_query_artifact(archive)
        target = metadata["target"]
        if target in targets:
            raise ValueError("duplicate query target")
        targets.add(target)
        versions.add(metadata["version"])
        if metadata["revision"] != revision:
            raise ValueError("query artifact was built from a different revision")
        if (archive.parent / f"SHA256SUMS.{target}").read_text() != checksum_line(
            archive
        ):
            raise ValueError("query archive SHA-256 mismatch")
    if targets != set(TARGETS) or len(versions) != 1:
        raise ValueError(
            "query release requires all three targets with the same version"
        )
    if output.exists() and any(output.iterdir()):
        raise ValueError("query output directory must be empty")
    output.mkdir(parents=True, exist_ok=True)
    for archive in archives:
        shutil.copyfile(archive, output / archive.name)
    (output / "SHA256SUMS").write_text(
        "".join(checksum_line(archive) for archive in archives)
    )


def smoke(archive: Path) -> None:
    metadata, files = read_query_artifact(archive)
    name = "abyss-query.exe" if metadata["target"] == WINDOWS_TARGET else "abyss-query"
    with tempfile.TemporaryDirectory(prefix="abyss-query-smoke-") as directory:
        executable = Path(directory) / name
        executable.write_bytes(files[name])
        executable.chmod(0o755)
        subprocess.run([str(executable), "--help"], check=True, capture_output=True)
        version = subprocess.check_output(
            [str(executable), "--version"], text=True
        ).strip()
        if version != f"abyss-query {metadata['version']}":
            raise ValueError("query executable version does not match the artifact")
        schema = json.loads(
            subprocess.check_output([str(executable), "schema"], text=True)
        )
        if not isinstance(schema, dict) or not schema:
            raise ValueError("query executable must emit a JSON schema")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    package = commands.add_parser("package", help="package one native query executable")
    package.add_argument("--target", choices=TARGETS, required=True)
    package.add_argument("--binaries", type=Path, required=True)
    package.add_argument("--output", type=Path, required=True)
    package.add_argument("--tag")
    assemble = commands.add_parser(
        "assemble", help="verify and assemble all three targets"
    )
    assemble.add_argument("--artifacts", type=Path, required=True)
    assemble.add_argument("--output", type=Path, required=True)
    assemble.add_argument("--revision", required=True)
    verify = commands.add_parser(
        "verify", help="validate archives and optional native smoke checks"
    )
    verify.add_argument("archives", type=Path, nargs="+")
    verify.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    if args.command == "package":
        print(package_query(args.target, args.binaries, args.output, args.tag))
    elif args.command == "assemble":
        assemble_queries(args.artifacts, args.output, args.revision)
        print(f"Assembled query release in {args.output}")
    else:
        for archive in args.archives:
            if args.smoke:
                smoke(archive)
            else:
                read_query_artifact(archive)
            print(f"Verified {archive.name}")


if __name__ == "__main__":
    main()
