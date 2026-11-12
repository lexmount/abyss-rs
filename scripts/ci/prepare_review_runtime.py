#!/usr/bin/env python3
"""Build an immutable, unpublished runtime for a dependent product's review.

The source tree must be clean at an explicitly selected commit. This creates
local review artifacts only; it never publishes a release or changes a pin.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile", choices=("debug", "release"), default="debug")
    args = parser.parse_args()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if revision != args.revision or subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT):
        parser.error("review builds require a clean checkout at the explicit full revision")
    metadata = subprocess.check_output(["rustc", "-vV"], text=True)
    target = next(line.removeprefix("host: ") for line in metadata.splitlines() if line.startswith("host: "))
    command = ["cargo", "build", "--locked", "--package", "abyss-broker", "--package", "abyss-delivery-plugin"]
    if args.profile == "release":
        command.append("--release")
    subprocess.run(command, cwd=ROOT, check=True)
    cargo = json.loads(subprocess.check_output(["cargo", "metadata", "--no-deps", "--format-version=1"], cwd=ROOT))
    source = Path(cargo["target_directory"]) / args.profile
    args.output.mkdir(parents=True, exist_ok=True)
    suffix = ".exe" if "windows" in target else ""
    files = {}
    for name in ("abyss-broker" + suffix, "abyss-delivery-plugin" + suffix):
        destination = args.output / name
        shutil.copy2(source / name, destination)
        files[name] = hashlib.sha256(destination.read_bytes()).hexdigest()
    manifest = {"schema_version":1, "kind":"development_runtime", "repository":"https://github.com/lexmount/abyss-rs",
        "revision":revision, "target":target, "profile":args.profile,
        "capabilities":["source_network_rules", "required_inspectors", "request_mutation", "authenticated_plugin_api"], "files":files}
    (args.output / "runtime-review.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(args.output / "runtime-review.json")


if __name__ == "__main__":
    main()
