#!/usr/bin/env python3
"""Exercise standalone query artifacts and the all-platform CDN release boundary."""

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

from package_cli import TARGETS, WINDOWS_TARGET
from package_query import (
    METADATA_FILE,
    assemble_queries,
    checksum_line,
    package_query,
    read_query_artifact,
)
from publish_cos import release_files


class QueryReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binaries = self.root / "binaries"
        self.binaries.mkdir()
        for name in ("abyss-query", "abyss-query.exe"):
            (self.binaries / name).write_bytes(f"fixture executable: {name}".encode())
        self.artifacts = self.root / "artifacts"
        self.archives = {
            target: package_query(target, self.binaries, self.artifacts / target, None)
            for target in TARGETS
        }
        metadata, _ = read_query_artifact(self.archives[TARGETS[0]])
        self.version = metadata["version"]
        self.revision = metadata["revision"]
        self.output = self.root / "release"

    def rewrite(self, target: str, change, update_checksum: bool = True) -> None:
        archive = self.archives[target]
        metadata, files = read_query_artifact(archive)
        change(metadata, files)
        files[METADATA_FILE] = json.dumps(metadata).encode()
        if archive.suffix == ".zip":
            with zipfile.ZipFile(archive, "w") as bundle:
                for name, data in files.items():
                    info = zipfile.ZipInfo(name)
                    info.external_attr = 0o100644 << 16
                    bundle.writestr(info, data)
        else:
            with tarfile.open(archive, "w:gz") as bundle:
                for name, data in files.items():
                    info = tarfile.TarInfo(name)
                    info.mode = 0o755 if name == "abyss-query" else 0o644
                    info.size = len(data)
                    bundle.addfile(info, io.BytesIO(data))
        if update_checksum:
            (archive.parent / f"SHA256SUMS.{target}").write_text(checksum_line(archive))

    def test_native_archives_preserve_executable_and_provenance(self) -> None:
        for target, archive in self.archives.items():
            with self.subTest(target=target):
                metadata, files = read_query_artifact(archive)
                name = "abyss-query.exe" if target == WINDOWS_TARGET else "abyss-query"
                self.assertEqual(set(files), {name, "LICENSE", "VERSION"})
                self.assertEqual(files[name], (self.binaries / name).read_bytes())
                self.assertEqual(metadata["target"], target)
                self.assertEqual(metadata["revision"], self.revision)
                self.assertEqual(metadata["version"], self.version)
                self.assertEqual(
                    metadata["files"],
                    {
                        name: hashlib.sha256(data).hexdigest()
                        for name, data in files.items()
                    },
                )
                if target != WINDOWS_TARGET:
                    with tarfile.open(archive) as bundle:
                        self.assertEqual(bundle.getmember(name).mode, 0o755)
                retry = package_query(target, self.binaries, self.root / "retry", None)
                self.assertEqual(archive.read_bytes(), retry.read_bytes())

    def test_assembled_release_satisfies_publisher_contract(self) -> None:
        assemble_queries(self.artifacts, self.output, self.revision)
        assets = release_files(self.output, f"v{self.version}", "abyss-query")
        self.assertEqual(len(assets), 4)
        self.assertEqual(assets[-1].name, "SHA256SUMS")
        self.assertEqual(set(self.output.iterdir()), set(assets))
        for target, archive in self.archives.items():
            self.assertEqual(
                archive.read_bytes(), (self.output / archive.name).read_bytes()
            )

    def test_missing_target_blocks_assembly_before_output(self) -> None:
        self.archives[WINDOWS_TARGET].unlink()
        with self.assertRaisesRegex(ValueError, "all three targets"):
            assemble_queries(self.artifacts, self.output, self.revision)
        self.assertFalse(self.output.exists())

    def test_duplicate_target_blocks_assembly(self) -> None:
        archive = self.archives[WINDOWS_TARGET]
        duplicate = self.artifacts / "duplicate" / archive.name
        duplicate.parent.mkdir()
        duplicate.write_bytes(archive.read_bytes())
        (duplicate.parent / f"SHA256SUMS.{WINDOWS_TARGET}").write_text(
            checksum_line(duplicate)
        )
        with self.assertRaisesRegex(ValueError, "duplicate query target"):
            assemble_queries(self.artifacts, self.output, self.revision)

    def test_mixed_revision_blocks_assembly(self) -> None:
        self.rewrite(
            WINDOWS_TARGET, lambda metadata, _: metadata.update(revision="f" * 40)
        )
        with self.assertRaisesRegex(ValueError, "different revision"):
            assemble_queries(self.artifacts, self.output, self.revision)

    def test_payload_corruption_blocks_assembly_even_with_valid_archive_checksum(
        self,
    ) -> None:
        self.rewrite(
            WINDOWS_TARGET,
            lambda _, files: files.update({"abyss-query.exe": b"corrupt"}),
        )
        with self.assertRaisesRegex(ValueError, "payload SHA-256"):
            assemble_queries(self.artifacts, self.output, self.revision)

    def test_archive_corruption_blocks_assembly(self) -> None:
        self.rewrite(
            WINDOWS_TARGET, lambda metadata, _: metadata.update(extra=True), False
        )
        with self.assertRaisesRegex(ValueError, "archive SHA-256"):
            assemble_queries(self.artifacts, self.output, self.revision)

    def test_unexpected_payload_is_rejected(self) -> None:
        self.rewrite(
            WINDOWS_TARGET,
            lambda _, files: files.update({"credentials.json": b"secret"}),
        )
        with self.assertRaisesRegex(ValueError, "unexpected query archive contents"):
            assemble_queries(self.artifacts, self.output, self.revision)

    def test_mixed_versions_block_assembly(self) -> None:
        def change(metadata, files):
            metadata["version"] = "99.0.0"
            files["VERSION"] = b"99.0.0\n"
            metadata["files"]["VERSION"] = hashlib.sha256(files["VERSION"]).hexdigest()

        self.rewrite(WINDOWS_TARGET, change)
        archive = self.archives[WINDOWS_TARGET]
        renamed = archive.with_name(archive.name.replace(self.version, "99.0.0"))
        archive.rename(renamed)
        (archive.parent / f"SHA256SUMS.{WINDOWS_TARGET}").write_text(
            checksum_line(renamed)
        )
        with self.assertRaisesRegex(ValueError, "same version"):
            assemble_queries(self.artifacts, self.output, self.revision)

    def test_invalid_tag_target_or_binary_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not match"):
            package_query(TARGETS[0], self.binaries, self.output, "v999.0.0")
        with self.assertRaisesRegex(ValueError, "unsupported"):
            package_query("not-a-target", self.binaries, self.output, None)
        binary = self.binaries / "abyss-query.exe"
        binary.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            package_query(WINDOWS_TARGET, self.binaries, self.output, None)
        binary.unlink()
        with self.assertRaisesRegex(ValueError, "regular file"):
            package_query(WINDOWS_TARGET, self.binaries, self.output, None)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
