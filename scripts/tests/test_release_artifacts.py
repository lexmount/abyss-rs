#!/usr/bin/env python3
"""Exercise release archives and the all-platform publication boundary."""

from __future__ import annotations

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

from assemble_release import assemble
from package_cli import package
from verify_release import read_artifact

MACOS = "aarch64-apple-darwin"
LINUX = "x86_64-unknown-linux-musl"
WINDOWS = "x86_64-pc-windows-msvc"


class ReleaseArtifactTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binaries = self.root / "binaries"
        self.binaries.mkdir()
        for name in (
            "abyss",
            "abyss-broker",
            "abyss-delivery-plugin",
            "abyss-broker.exe",
            "abyss-delivery-plugin.exe",
        ):
            (self.binaries / name).write_bytes(f"fixture executable: {name}".encode())
        self.artifacts = self.root / "artifacts"
        self.archives = {}
        for target in (MACOS, LINUX, WINDOWS):
            for variant in (
                ("runtime",) if target == WINDOWS else ("default", "no-local")
            ):
                self.archives[target, variant] = package(
                    target, self.binaries, self.artifacts / target, None, variant
                )
        metadata, _ = read_artifact(self.archives[MACOS, "default"])
        self.version = metadata["version"]
        self.revision = metadata["revision"]
        self.output = self.root / "release"

    def rewrite(
        self, identity: tuple[str, str], change, update_checksum: bool = True
    ) -> None:
        archive = self.archives[identity]
        metadata, files = read_artifact(archive)
        change(metadata, files)
        files["endpoint-artifact.json"] = json.dumps(metadata).encode()
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive, "w") as bundle:
                for name, data in files.items():
                    bundle.writestr(name, data)
        else:
            with tarfile.open(archive, "w:gz") as bundle:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
        if update_checksum:
            target, variant = identity
            suffix = "" if variant == "default" else f".{variant}"
            checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
            (archive.parent / f"SHA256SUMS.{target}{suffix}").write_text(
                f"{checksum}  {archive.name}\n"
            )

    def test_complete_release_retains_public_names_and_contains_all_variants(
        self,
    ) -> None:
        assemble(self.artifacts, self.output, self.revision)
        expected = {
            "install.sh",
            "SHA256SUMS",
            f"abyss-runtime-v{self.version}-{WINDOWS}.zip",
        }
        for target in (MACOS, LINUX):
            expected.add(f"abyss-cli-v{self.version}-{target}.tar.gz")
            expected.add(f"abyss-cli-v{self.version}-{target}-no-local.tar.gz")
        self.assertEqual({path.name for path in self.output.iterdir()}, expected)
        checksums = (self.output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(checksums), 5)
        for line in checksums:
            digest, name = line.split("  ")
            self.assertEqual(
                digest, hashlib.sha256((self.output / name).read_bytes()).hexdigest()
            )

    def test_windows_runtime_has_executables_and_exact_driver_abi(self) -> None:
        archive = self.archives[WINDOWS, "runtime"]
        metadata, files = read_artifact(archive)
        self.assertEqual(
            set(files),
            {
                "abyss-broker.exe",
                "abyss-delivery-plugin.exe",
                "abyss_callout_abi.h",
                "LICENSE",
                "VERSION",
            },
        )
        self.assertEqual(
            files["abyss_callout_abi.h"],
            (ROOT / "crates/abyss-broker/include/abyss_callout_abi.h")
            .read_text(encoding="utf-8")
            .encode("utf-8"),
        )
        self.assertNotIn("abyss-cli", metadata["features"])
        self.assertFalse((archive.parent / "install.sh").exists())

    def test_cli_variants_keep_runtime_and_distinct_checksums(self) -> None:
        for target in (MACOS, LINUX):
            default, payload = read_artifact(self.archives[target, "default"])
            no_local, other_payload = read_artifact(self.archives[target, "no-local"])
            self.assertEqual(default["features"]["abyss-cli"], ["local"])
            self.assertEqual(no_local["features"]["abyss-cli"], [])
            for name in ("abyss-broker", "abyss-delivery-plugin"):
                self.assertEqual(payload[name], other_payload[name])
            self.assertTrue(
                (self.artifacts / target / f"SHA256SUMS.{target}").is_file()
            )
            self.assertTrue(
                (self.artifacts / target / f"SHA256SUMS.{target}.no-local").is_file()
            )
            with tarfile.open(self.archives[target, "no-local"]) as bundle:
                self.assertEqual(bundle.getmember("abyss").mode, 0o755)

    def test_missing_platform_blocks_assembly(self) -> None:
        self.archives[WINDOWS, "runtime"].unlink()
        with self.assertRaisesRegex(ValueError, "all five"):
            assemble(self.artifacts, self.output, self.revision)
        self.assertFalse(self.output.exists())

    def test_mixed_revisions_block_assembly(self) -> None:
        self.rewrite(
            (WINDOWS, "runtime"), lambda metadata, _: metadata.update(revision="f" * 40)
        )
        with self.assertRaisesRegex(ValueError, "different revision"):
            assemble(self.artifacts, self.output, self.revision)

    def test_corrupted_payload_is_rejected(self) -> None:
        identity = (LINUX, "no-local")
        self.rewrite(
            identity, lambda _, files: files.update(abyss=b"changed executable")
        )
        with self.assertRaisesRegex(ValueError, "payload SHA-256"):
            read_artifact(self.archives[identity])

    def test_incorrect_variant_metadata_is_rejected(self) -> None:
        identity = (MACOS, "no-local")
        self.rewrite(
            identity,
            lambda metadata, _: metadata["features"].update({"abyss-cli": ["local"]}),
        )
        with self.assertRaisesRegex(ValueError, "features"):
            read_artifact(self.archives[identity])

    def test_archive_checksum_mismatch_blocks_assembly(self) -> None:
        self.rewrite(
            (WINDOWS, "runtime"), lambda _metadata, _files: None, update_checksum=False
        )
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            assemble(self.artifacts, self.output, self.revision)

    def test_different_runtime_between_cli_variants_blocks_assembly(self) -> None:
        def change(metadata, files):
            files["abyss-broker"] = b"different broker"
            metadata["files"]["abyss-broker"] = hashlib.sha256(
                files["abyss-broker"]
            ).hexdigest()

        self.rewrite((MACOS, "no-local"), change)
        with self.assertRaisesRegex(ValueError, "identical broker"):
            assemble(self.artifacts, self.output, self.revision)

    def test_duplicate_variant_blocks_assembly(self) -> None:
        archive = self.archives[MACOS, "default"]
        duplicate = self.artifacts / "duplicate" / archive.name
        duplicate.parent.mkdir()
        duplicate.write_bytes(archive.read_bytes())
        for checksum in archive.parent.glob("SHA256SUMS.*"):
            (duplicate.parent / checksum.name).write_bytes(checksum.read_bytes())
        with self.assertRaisesRegex(ValueError, "duplicate"):
            assemble(self.artifacts, self.output, self.revision)

    def test_packaging_rejects_missing_binaries_and_invalid_target_variants(
        self,
    ) -> None:
        for target, variant in (
            (WINDOWS, "default"),
            (WINDOWS, "no-local"),
            (MACOS, "runtime"),
        ):
            with self.subTest(target=target, variant=variant), self.assertRaisesRegex(
                ValueError, "Windows"
            ):
                package(target, self.binaries, self.output, None, variant)
        (self.binaries / "abyss-delivery-plugin.exe").unlink()
        with self.assertRaises(FileNotFoundError):
            package(WINDOWS, self.binaries, self.output, None, "runtime")
        self.assertFalse(self.output.exists())

    def test_tag_mismatch_blocks_every_variant(self) -> None:
        for target, variant in ((MACOS, "no-local"), (WINDOWS, "runtime")):
            with self.subTest(target=target), self.assertRaisesRegex(
                ValueError, "does not match"
            ):
                package(target, self.binaries, self.output, "v999.0.0", variant)


if __name__ == "__main__":
    unittest.main()
