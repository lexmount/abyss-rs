#!/usr/bin/env python3
"""Exercise the piped POSIX installer against real archives and checksums."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LINUX = "x86_64-unknown-linux-musl"
MACOS = "aarch64-apple-darwin"
BINARIES = ("abyss", "abyss-broker", "abyss-delivery-plugin")


class ReleaseInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
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
        cls.version = next(
            package["version"]
            for package in metadata["packages"]
            if package["name"] == "abyss-cli"
        )

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = self.root / "commands"
        self.commands.mkdir()
        self.binaries = self.root / "binaries"
        self.binaries.mkdir()
        for binary in BINARIES:
            path = self.binaries / binary
            path.write_text(
                f'#!/bin/sh\nif [ "$1" = version ]; then echo {self.version}; fi\n'
            )
            path.chmod(0o755)
        self.release = self.root / "release"
        for target in (LINUX, MACOS):
            result = self.package(target)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.checksums()
        self.command(
            "uname",
            '#!/bin/sh\ncase "$1" in -s) echo "$TEST_OS";; -m) echo "$TEST_ARCH";; esac\n',
        )
        self.command(
            "curl",
            f"#!{sys.executable}\n"
            + """
import os
import shutil
import sys
from pathlib import Path
args = sys.argv[1:]
assert args[args.index('--proto') + 1] == '=https'
assert args[args.index('--proto-redir') + 1] == '=https'
with open(os.environ['TEST_DOWNLOAD_LOG'], 'a') as log:
    log.write(args[-1] + '\\n')
if os.environ.get('TEST_DOWNLOAD_FAIL'):
    sys.exit(22)
shutil.copyfile(Path(os.environ['TEST_RELEASE']) / args[-1].rsplit('/', 1)[1],
                args[args.index('-o') + 1])
""",
        )
        for name in ("sudo", "systemctl"):
            self.command(
                name,
                "#!/bin/sh\necho 'unexpected privilege/systemd access' >&2\nexit 91\n",
            )
        self.stage = self.root / "stage"
        self.download_log = self.root / "downloads"
        self.env = {
            **os.environ,
            "PATH": f"{self.commands}:{os.environ['PATH']}",
            "DESTDIR": str(self.stage),
            "TMPDIR": str(self.root),
            "TEST_OS": "Linux",
            "TEST_ARCH": "x86_64",
            "TEST_RELEASE": str(self.release),
            "TEST_DOWNLOAD_LOG": str(self.download_log),
        }

    def command(self, name: str, content: str) -> None:
        path = self.commands / name
        path.write_text(content)
        path.chmod(0o755)

    def package(
        self, target: str, tag: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/ci/package_cli.py"),
                "--target",
                target,
                "--binaries",
                str(self.binaries),
                "--output",
                str(self.release),
                "--tag",
                tag if tag is not None else f"v{self.version}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

    def checksums(self) -> None:
        (self.release / "SHA256SUMS").write_text(
            "".join(
                path.read_text() for path in sorted(self.release.glob("SHA256SUMS.*"))
            )
        )

    def run_installer(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["/bin/sh", "-s", "--", *args],
            input=(self.release / "install.sh").read_text(),
            env={**self.env, **env},
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_cleaned(self) -> None:
        self.assertFalse(list(self.root.glob("abyss-download.*")))
        self.assertFalse(list(self.stage.rglob(".abyss-install.*")))

    def test_linux_piped_install_and_repeat_preserve_configuration(self) -> None:
        config = self.stage / "home/user/.abyss/product-config.json"
        config.parent.mkdir(parents=True)
        config.write_text("existing configuration")
        for _ in range(2):
            result = self.run_installer("--prefix", "/opt/abyss")
            self.assertEqual(result.returncode, 0, result.stderr)
            for name in BINARIES:
                installed = self.stage / "opt/abyss/bin" / name
                self.assertEqual(
                    installed.read_bytes(), (self.binaries / name).read_bytes()
                )
                self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
            unit = self.stage / "etc/systemd/system/abyss-broker@.service"
            self.assertIn("ExecStart=/opt/abyss/bin/abyss-broker ", unit.read_text())
            self.assertNotIn(str(self.stage), unit.read_text())
            self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
            self.assertEqual(config.read_text(), "existing configuration")
            self.assert_cleaned()
        self.assertTrue(
            all(
                f"/releases/download/v{self.version}/" in url
                for url in self.download_log.read_text().splitlines()
            )
        )

    def test_macos_picks_native_archive_without_service(self) -> None:
        result = self.run_installer(TEST_OS="Darwin", TEST_ARCH="arm64")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.stage / "usr/local/bin/abyss").exists())
        self.assertFalse((self.stage / "etc").exists())
        self.assertIn(MACOS, self.download_log.read_text())
        self.assert_cleaned()

    def test_download_and_checksum_failures_leave_old_installation(self) -> None:
        old = self.stage / "usr/local/bin/abyss"
        old.parent.mkdir(parents=True)
        old.write_text("old executable")
        result = self.run_installer(TEST_DOWNLOAD_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(old.read_text(), "old executable")
        archive = self.release / f"abyss-cli-v{self.version}-{LINUX}.tar.gz"
        archive.write_bytes(archive.read_bytes() + b"corrupted")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SHA-256 mismatch", result.stderr)
        self.assertEqual(old.read_text(), "old executable")
        self.assert_cleaned()

    def test_checksum_missing_duplicate_and_invalid_archive(self) -> None:
        checksum = self.release / "SHA256SUMS"
        original = checksum.read_text()
        for value in ("", original + original):
            checksum.write_text(value)
            result = self.run_installer()
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing or duplicate", result.stderr)
        archive = self.release / f"abyss-cli-v{self.version}-{LINUX}.tar.gz"
        archive.write_bytes(b"not a tarball")
        checksum.write_text(
            f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n"
        )
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid release archive", result.stderr)
        self.assertFalse(self.stage.exists())
        self.assert_cleaned()

    def test_unrunnable_binary_fails_before_replacement(self) -> None:
        (self.binaries / "abyss-broker").write_text("#!/bin/sh\nexit 7\n")
        self.assertEqual(self.package(LINUX).returncode, 0)
        self.checksums()
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot run on this system", result.stderr)
        self.assertFalse(self.stage.exists())
        self.assert_cleaned()

    def test_invalid_platform_options_and_version_do_not_download(self) -> None:
        for args, env in [
            (("--version", "../../bad"), {}),
            (("--prefix", "relative"), {}),
            (("--prefix", "/bad%prefix"), {}),
            (("--unknown",), {}),
            (("--prefix",), {}),
            ((), {"TEST_OS": "Linux", "TEST_ARCH": "aarch64"}),
            ((), {"TEST_OS": "FreeBSD"}),
        ]:
            with self.subTest(args=args, env=env):
                self.assertNotEqual(self.run_installer(*args, **env).returncode, 0)
                self.assertFalse(self.download_log.exists())
        self.assertEqual(self.run_installer("--help").returncode, 0)

    def test_release_tag_must_match_workspace(self) -> None:
        result = self.package(LINUX, "v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match workspace", result.stderr)


if __name__ == "__main__":
    unittest.main()
