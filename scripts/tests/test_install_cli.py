#!/usr/bin/env python3
"""Exercise source installation in temporary roots with a simulated compiler."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "scripts" / "install-cli.sh"
BINARIES = ("abyss", "abyss-broker", "abyss-delivery-plugin")
FAKE_TOOL = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys

name = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["TEST_CALLS"], "a", encoding="utf-8") as log:
    log.write(json.dumps([name, *args]) + "\n")
if name == "uname":
    print(os.environ["TEST_PLATFORM"])
elif name == "rustc":
    print("host: " + os.environ["TEST_TARGET"])
elif name == "cargo":
    if os.environ.get("TEST_BUILD_FAIL"):
        sys.exit(17)
    target = args[args.index("--target") + 1]
    root = Path(args[args.index("--target-dir") + 1]) / target / "release"
    root.mkdir(parents=True, exist_ok=True)
    for binary in ("abyss", "abyss-broker", "abyss-delivery-plugin"):
        if binary == os.environ.get("TEST_MISSING_BINARY"):
            continue
        code = 19 if binary == os.environ.get("TEST_BAD_BINARY") else 0
        path = root / binary
        path.write_text(f"#!/bin/sh\nprintf 'fixture {binary}\\n'\nexit {code}\n")
        path.chmod(0o755)
elif name == "install":
    if args[-1].endswith("/abyss-delivery-plugin"):
        sys.exit(20)
    sys.exit(subprocess.call([os.environ["TEST_REAL_INSTALL"], *args]))
else:
    # Staged installs must never ask for privileges or change live services.
    sys.exit(21)
"""


class InstallCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="abyss-source-install-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "tools"
        self.tools.mkdir()
        self.stage = self.root / "staging"
        self.calls = self.root / "calls.jsonl"
        self.environment = os.environ.copy()
        for name in ("CARGO_TARGET_DIR", "DESTDIR"):
            self.environment.pop(name, None)
        self.environment.update(
            PATH=f"{self.tools}{os.pathsep}{os.environ['PATH']}",
            DESTDIR=str(self.stage),
            CARGO_TARGET_DIR=str(self.root / "build outputs"),
            TEST_CALLS=str(self.calls),
            TEST_PLATFORM="Darwin",
            TEST_TARGET="aarch64-apple-darwin",
        )
        for name in ("cargo", "rustc", "uname", "sudo", "systemctl"):
            self.fake_tool(name)

    def fake_tool(self, name: str) -> None:
        path = self.tools / name
        path.write_text(FAKE_TOOL, encoding="utf-8")
        path.chmod(0o755)

    def run_installer(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        # Invocation must work outside the repository's working directory.
        return subprocess.run(
            ["bash", str(INSTALLER), *arguments],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def recorded_calls(self) -> list[list[str]]:
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def assert_success(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_macos_installs_all_sibling_binaries_with_native_target(self) -> None:
        self.environment["CARGO_BUILD_TARGET"] = "wasm32-unknown-unknown"
        result = self.run_installer("--prefix", "/Applications/Abyss CLI")
        self.assert_success(result)
        binary_dir = self.stage / "Applications/Abyss CLI/bin"
        for binary in BINARIES:
            installed = binary_dir / binary
            self.assertTrue(installed.is_file())
            self.assertEqual(installed.stat().st_mode & 0o777, 0o755)
        calls = self.recorded_calls()
        build = next(call for call in calls if call[0] == "cargo")
        self.assertIn("--release", build)
        self.assertIn("--locked", build)
        self.assertEqual(build[build.index("--target") + 1], "aarch64-apple-darwin")
        self.assertEqual(
            {build[index + 1] for index, arg in enumerate(build) if arg == "--package"},
            {"abyss-cli", "abyss-broker", "abyss-delivery-plugin"},
        )
        self.assertFalse(any(call[0] in ("sudo", "systemctl") for call in calls))
        self.assertFalse(list(binary_dir.glob(".abyss-install.*")))

    def test_linux_stages_unit_with_runtime_prefix_and_preserves_state(self) -> None:
        self.environment.update(
            TEST_PLATFORM="Linux", TEST_TARGET="x86_64-unknown-linux-gnu"
        )
        state = self.stage / "home/test/.abyss/product-config.json"
        state.parent.mkdir(parents=True)
        state.write_text("deployment-owned")
        result = self.run_installer("--prefix", "/opt/abyss")
        self.assert_success(result)
        unit = self.stage / "etc/systemd/system/abyss-broker@.service"
        source = unit.read_text()
        self.assertIn("ExecStart=/opt/abyss/bin/abyss-broker ", source)
        self.assertNotIn(str(self.stage), source)
        self.assertIn("User=%i", source)
        self.assertIn("--config /home/%i/.abyss/broker-config.toml", source)
        self.assertEqual(unit.stat().st_mode & 0o777, 0o644)
        self.assertEqual(state.read_text(), "deployment-owned")
        self.assertFalse(
            any(call[0] in ("sudo", "systemctl") for call in self.recorded_calls())
        )
        for binary in BINARIES:
            self.assertTrue((self.stage / "opt/abyss/bin" / binary).is_file())

    def test_build_and_smoke_failures_preserve_existing_installation(self) -> None:
        destination = self.stage / "usr/local/bin"
        destination.mkdir(parents=True)
        for binary in BINARIES:
            (destination / binary).write_text("previous installation")
        for failure, value in (
            ("TEST_BUILD_FAIL", "1"),
            ("TEST_MISSING_BINARY", "abyss"),
            ("TEST_BAD_BINARY", "abyss-delivery-plugin"),
        ):
            with self.subTest(failure=failure):
                self.environment[failure] = value
                result = self.run_installer()
                self.assertNotEqual(result.returncode, 0)
                for binary in BINARIES:
                    self.assertEqual(
                        (destination / binary).read_text(), "previous installation"
                    )
                self.environment.pop(failure)

    def test_copy_failure_cleans_staging_before_replacing_binaries(self) -> None:
        self.environment["TEST_REAL_INSTALL"] = (
            shutil.which("install") or "/usr/bin/install"
        )
        self.fake_tool("install")
        destination = self.stage / "usr/local/bin"
        destination.mkdir(parents=True)
        (destination / "abyss").write_text("previous installation")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((destination / "abyss").read_text(), "previous installation")
        self.assertFalse(list(destination.glob(".abyss-install.*")))

    def test_reinstallation_replaces_files_and_does_not_follow_binary_symlink(
        self,
    ) -> None:
        self.assert_success(self.run_installer())
        binary = self.stage / "usr/local/bin/abyss"
        foreign = self.root / "foreign-binary"
        foreign.write_text("unrelated")
        binary.unlink()
        binary.symlink_to(foreign)
        self.assert_success(self.run_installer())
        self.assertFalse(binary.is_symlink())
        self.assertEqual(foreign.read_text(), "unrelated")

    def test_live_macos_install_prints_path_and_verifies_cli(self) -> None:
        self.environment.pop("DESTDIR")
        prefix = self.root / "user prefix"
        result = self.run_installer("--prefix", str(prefix))
        self.assert_success(result)
        self.assertTrue((prefix / "bin/abyss").is_file())
        self.assertIn("fixture abyss", result.stdout)
        self.assertIn("export PATH=", result.stdout)
        self.assertIn("abyss deploy-local start", result.stdout)

    def test_linux_without_systemd_fails_before_build(self) -> None:
        self.environment.update(
            TEST_PLATFORM="Linux", TEST_TARGET="x86_64-unknown-linux-gnu"
        )
        self.environment.pop("DESTDIR")
        result = self.run_installer()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("systemd must be running", result.stderr)
        self.assertFalse(any(call[0] == "cargo" for call in self.recorded_calls()))

    def test_help_and_invalid_inputs_do_not_build(self) -> None:
        self.assert_success(self.run_installer("--help"))
        for args in (("--prefix",), ("--prefix", "relative"), ("--unknown",)):
            with self.subTest(args=args):
                self.assertNotEqual(self.run_installer(*args).returncode, 0)
        self.environment["TEST_PLATFORM"] = "Windows_NT"
        self.assertNotEqual(self.run_installer().returncode, 0)
        self.environment["TEST_PLATFORM"] = "Linux"
        self.assertNotEqual(
            self.run_installer("--prefix", "/tmp/bad%prefix").returncode, 0
        )
        self.assertFalse(any(call[0] == "cargo" for call in self.recorded_calls()))


if __name__ == "__main__":
    unittest.main()
