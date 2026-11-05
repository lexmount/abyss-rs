#!/usr/bin/env python3
"""Exercise CDN publication boundaries without credentials or cloud writes."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/ci"))

from package_broker import broker_archive_name
from package_cli import TARGETS
from publish_broker_cos import publish


class BrokerCosTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "release"
        self.source.mkdir()
        self.tag = "v1.2.3"
        for target in TARGETS:
            (self.source / broker_archive_name(self.tag, target)).write_bytes(
                target.encode()
            )
        self.checksums = "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in sorted(self.source.iterdir())
        )
        (self.source / "SHA256SUMS").write_text(self.checksums)
        self.env = patch.dict(
            os.environ,
            {
                "TENCENTCLOUD_SECRET_ID": "fixture-id",
                "TENCENTCLOUD_SECRET_KEY": "fixture-key",
                "RUNNER_TEMP": str(self.root),
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)
        self.calls = []

    def invoke(self, bucket="example-123456", region="ap-nanjing", tag=None) -> None:
        publish(self.source, tag or self.tag, bucket, region, self.root / "coscli")

    def record_upload(self, argv, *, env, check):
        self.assertTrue(check)
        self.assertNotIn("TENCENTCLOUD_SECRET_ID", env)
        self.assertNotIn("TENCENTCLOUD_SECRET_KEY", env)
        self.assertNotIn("fixture-id", " ".join(argv))
        self.assertNotIn("fixture-key", " ".join(argv))
        config = Path(argv[argv.index("--config-path") + 1])
        base = json.loads(config.read_text())["cos"]["base"]
        self.assertEqual(base["secretid"], "fixture-id")
        self.assertEqual(base["secretkey"], "fixture-key")
        self.assertEqual(base["protocol"], "https")
        if os.name != "nt":
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(config.parent.stat().st_mode & 0o777, 0o700)
        self.calls.append((argv, config))

    def test_both_regions_use_versioned_broker_prefix_and_publish_checksums_last(self):
        for region in ("ap-nanjing", "ap-hongkong"):
            with (
                self.subTest(region=region),
                patch(
                    "publish_broker_cos.subprocess.run", side_effect=self.record_upload
                ),
            ):
                self.calls.clear()
                self.invoke(region=region)
                self.assertEqual(len(self.calls), 4)
                for argv, config in self.calls:
                    self.assertTrue(
                        argv[3].startswith("cos://example-123456/broker/v1.2.3/")
                    )
                    self.assertEqual(
                        argv[argv.index("--endpoint") + 1], f"cos.{region}.myqcloud.com"
                    )
                    self.assertFalse(config.exists())
                    self.assertIn("--disable-log=true", argv)
                self.assertTrue(self.calls[-1][0][3].endswith("/SHA256SUMS"))

    def test_upload_failure_stops_before_completion_marker_and_removes_credentials(
        self,
    ):
        def fail(argv, **kwargs):
            self.record_upload(argv, **kwargs)
            raise subprocess.CalledProcessError(1, argv)

        with patch("publish_broker_cos.subprocess.run", side_effect=fail):
            with self.assertRaises(subprocess.CalledProcessError):
                self.invoke()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(self.calls[0][1].parent.exists())
        self.assertFalse(self.calls[0][0][3].endswith("/SHA256SUMS"))

    def test_invalid_destination_tag_and_credentials_never_upload(self):
        with patch("publish_broker_cos.subprocess.run") as upload:
            for options in (
                {"bucket": ""},
                {"bucket": "example/other-123"},
                {"region": ""},
                {"region": "../region"},
                {"tag": "v1.2.3/../../releases/latest"},
                {"tag": "main"},
                {"tag": "v9.9.9"},
            ):
                with self.subTest(options=options), self.assertRaises(ValueError):
                    self.invoke(**options)
            with patch.dict(os.environ, {"TENCENTCLOUD_SECRET_KEY": ""}):
                with self.assertRaisesRegex(ValueError, "TENCENTCLOUD_SECRET_KEY"):
                    self.invoke()
            upload.assert_not_called()

    def test_missing_extra_or_corrupted_assets_never_upload(self):
        archive = next(self.source.glob("*.zip"))
        original = archive.read_bytes()
        with patch("publish_broker_cos.subprocess.run") as upload:
            archive.unlink()
            with self.assertRaisesRegex(ValueError, "exactly three"):
                self.invoke()
            archive.write_bytes(b"corruption")
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.invoke()
            archive.write_bytes(original)
            (self.source / "credentials.yaml").write_text("must never be uploaded")
            with self.assertRaisesRegex(ValueError, "exactly three"):
                self.invoke()
            upload.assert_not_called()


if __name__ == "__main__":
    unittest.main()
