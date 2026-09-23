#!/usr/bin/env python3
"""Validate and publish the broker, Rust SDK, and their dependencies to crates.io."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tomllib
from urllib.error import HTTPError
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[2]
# Dependencies must appear before their consumers. Other workspace crates remain unpublished.
PACKAGES = (
    "abyss-plugin-protocol",
    "abyss-storage",
    "abyss-mitm",
    "abyss-agent-hook",
    "abyss-broker",
    "abyss-sdk",
)


def validate_release(workspace, metadata, tag):
    """Reject tag/version drift and any change outside the agreed release set."""
    version = workspace["workspace"]["package"]["version"]
    if tag is not None and tag != f"v{version}":
        raise ValueError(f"tag {tag!r} must equal workspace version v{version}")
    members = set(metadata["workspace_members"])
    packages = {
        package["name"]: package
        for package in metadata["packages"]
        if package["id"] in members
    }
    publishable = {name for name, package in packages.items() if package["publish"] != []}
    if publishable != set(PACKAGES):
        raise ValueError(f"publishable crates must be exactly {', '.join(PACKAGES)}")
    preceding = set()
    for name in PACKAGES:
        package = packages[name]
        if package["version"] != version or package["publish"] != ["crates-io"]:
            raise ValueError(f"{name} must use version {version} and publish = ['crates-io']")
        if not package["description"] or not package["readme"]:
            raise ValueError(f"{name} needs a description and README")
        for dependency in package["dependencies"]:
            if dependency.get("kind") == "dev":
                continue
            if dependency.get("path") is not None:
                dependency_name = dependency["name"]
                if dependency_name not in preceding:
                    raise ValueError(f"{name}: unpublished or unordered dependency {dependency_name}")
                if dependency["req"] not in (version, f"^{version}", f"={version}"):
                    raise ValueError(f"{name}: {dependency_name} must require version {version}")
            if dependency.get("source", "") and dependency["source"].startswith("git+"):
                raise ValueError(f"{name}: git dependencies cannot be published to crates.io")
        preceding.add(name)
    return version


def check_release(tag):
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        workspace = tomllib.load(manifest)
    metadata = json.loads(subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"], cwd=ROOT
    ))
    version = validate_release(workspace, metadata, tag)
    fixture = ROOT / "specs/broker-plugin-protocol/v1/fixtures/agent-event.json"
    packaged_fixture = ROOT / "crates/abyss-broker/src/plugin/fixtures/agent-event.json"
    if fixture.read_bytes() != packaged_fixture.read_bytes():
        raise ValueError("broker's packaged AgentEvent fixture must match the public specification")
    contract = ROOT / "specs/broker-plugin-protocol/v1"
    packaged_contract = ROOT / "crates/abyss-sdk/tests/fixtures/broker-plugin-protocol/v1"
    for source in sorted(contract.rglob("*.json")):
        relative = source.relative_to(contract)
        if source.read_bytes() != (packaged_contract / relative).read_bytes():
            raise ValueError(f"SDK's packaged {relative} must match the public specification")
    print(f"Validated crates.io release {version}: {', '.join(PACKAGES)}", flush=True)
    return version


def published_version(name, version):
    """Only an index 404 means missing; network/auth/server failures stop publication."""
    if name not in PACKAGES:
        raise ValueError(f"crate is outside the crates.io release set: {name}")
    request = Request(
        f"https://index.crates.io/{name[:2]}/{name[2:4]}/{name}",
        headers={"User-Agent": "abyss-rs-release (https://github.com/lexmount/abyss-rs)"},
    )
    try:
        with urlopen(request, timeout=30) as response:
            entries = response.read().decode("utf-8").splitlines()
    except HTTPError as error:
        if error.code == 404:
            return False
        raise
    for line in entries:
        entry = json.loads(line)
        if entry["vers"] == version:
            if entry["yanked"]:
                raise ValueError(f"{name} {version} is yanked; release a new version")
            return True
    return False


def publish_release(version):
    if not os.environ.get("CARGO_REGISTRY_TOKEN", "").strip():
        raise ValueError("CARGO_REGISTRY_TOKEN is required for publication")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT).strip():
        raise ValueError("publication requires a clean Git checkout")
    # Check the entire set before uploading anything, including yanked versions.
    existing = {name: published_version(name, version) for name in PACKAGES}
    for name in PACKAGES:
        if existing[name]:
            print(f"Skipping {name} {version}: already published", flush=True)
            continue
        print(f"Publishing {name} {version}", flush=True)
        # Cargo waits for index visibility before the next dependent is published.
        # On an upload/index timeout, stop; rerunning checks the index before retrying.
        subprocess.run(
            ["cargo", "publish", "--locked", "--registry", "crates-io", "--package", name],
            cwd=ROOT, check=True,
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "dry-run", "publish"))
    parser.add_argument("--tag", help="must match v<workspace.package.version>")
    parser.add_argument("--allow-dirty", action="store_true", help="local dry-run only")
    args = parser.parse_args()
    if args.command == "publish" and not args.tag:
        parser.error("publish requires --tag")
    if args.allow_dirty and args.command != "dry-run":
        parser.error("--allow-dirty is only supported for dry-run")
    try:
        version = check_release(args.tag)
        if args.command == "dry-run":
            command = ["cargo", "publish", "--locked", "--dry-run", "--registry", "crates-io"]
            for name in PACKAGES:
                command.extend(["--package", name])
            if args.allow_dirty:
                command.append("--allow-dirty")
            subprocess.run(command, cwd=ROOT, check=True)
        elif args.command == "publish":
            publish_release(version)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
