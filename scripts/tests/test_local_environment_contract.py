#!/usr/bin/env python3
"""Contracts for the public, Docker-free local environment bootstrap."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "scripts" / "install-local.sh"
MANAGER = REPO_ROOT / "scripts" / "abyss-local"
README = REPO_ROOT / "README.md"


class LocalEnvironmentContractTests(unittest.TestCase):
    def test_external_components_are_public_and_version_pinned(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn("https://github.com/lexmount/abyss-rs.git", source)
        self.assertIn("https://github.com/lexmount/abyss-backend.git", source)
        self.assertRegex(
            source,
            r'DEFAULT_BACKEND_REVISION="[0-9a-f]{40}"',
        )
        self.assertRegex(
            source,
            r'DEFAULT_DASHBOARD_PACKAGE="@lexmount\.com/abyss-dashboard@[0-9]+\.[0-9]+\.[0-9]+"',
        )

    def test_installer_builds_only_the_native_storage_profile(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        for package in ("abyss-cli", "abyss-broker", "abyss-delivery-plugin"):
            self.assertIn(f"--package {package}", source)
        self.assertIn("--package abyss-backend", source)
        self.assertIn("--no-default-features", source)
        self.assertIn("--features sqlite-fts", source)
        self.assertNotIn("docker", source.lower())

    def test_manager_uses_loopback_and_private_credential_files(self) -> None:
        source = MANAGER.read_text(encoding="utf-8")

        self.assertIn('readonly BACKEND_HOST="127.0.0.1"', source)
        self.assertIn('readonly DASHBOARD_HOST="127.0.0.1"', source)
        self.assertIn('"mode": "authorization_header_file"', source)
        self.assertIn('atomic_write "${TOKEN_FILE}" 600', source)
        self.assertIn('atomic_write "${AUTHORIZATION_FILE}" 600', source)
        self.assertNotIn("docker", source.lower())

    def test_readme_exposes_one_line_install_and_lifecycle(self) -> None:
        source = README.read_text(encoding="utf-8")

        self.assertIn("scripts/install-local.sh | bash", source)
        self.assertIn("abyss-local status", source)
        self.assertIn("abyss-local stop", source)
        self.assertIn("abyss run -- codex", source)


if __name__ == "__main__":
    unittest.main()
