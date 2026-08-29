#!/usr/bin/env python3
"""Contracts for the CLI-managed, Docker-free local environment."""

from __future__ import annotations

import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
INSTALLER = REPO_ROOT / "scripts" / "install-local.sh"
DEPLOY_LOCAL = REPO_ROOT / "crates" / "abyss-cli" / "src" / "deploy_local"
README = REPO_ROOT / "README.md"


class LocalEnvironmentContractTests(unittest.TestCase):
    def test_runtime_components_are_public_and_version_pinned(self) -> None:
        config = (DEPLOY_LOCAL / "config.rs").read_text(encoding="utf-8")
        artifacts = (DEPLOY_LOCAL / "artifacts.rs").read_text(encoding="utf-8")

        self.assertIn("https://github.com/lexmount/abyss-backend/releases/download", artifacts)
        self.assertRegex(config, r'BACKEND_VERSION: &str = "[0-9]+\.[0-9]+\.[0-9]+"')
        self.assertRegex(
            config,
            r'DASHBOARD_PACKAGE: &str = "@lexmount\.com/abyss-dashboard@[0-9]+\.[0-9]+\.[0-9]+"',
        )
        self.assertIn("SHA256SUMS", artifacts)

    def test_installer_only_installs_the_original_cli_runtime(self) -> None:
        source = INSTALLER.read_text(encoding="utf-8")

        self.assertIn('${BASH_SOURCE[0]}', source)
        self.assertIn('ABYSS_RS_SOURCE="$(cd -- "${SCRIPT_DIR}/.."', source)
        for package in ("abyss-cli", "abyss-broker", "abyss-delivery-plugin"):
            self.assertIn(f"--package {package}", source)
        self.assertNotIn("abyss-backend.git", source)
        self.assertNotIn("--package abyss-backend", source)
        self.assertNotIn("npm install", source)
        self.assertNotIn("abyss-local", source)
        self.assertNotIn("docker", source.lower())
        self.assertIn('"${RUNTIME_BIN_DIR}/abyss" deploy-local start', source)

    def test_cli_owns_loopback_ports_and_private_credentials(self) -> None:
        source = (DEPLOY_LOCAL / "mod.rs").read_text(encoding="utf-8")
        config = (DEPLOY_LOCAL / "config.rs").read_text(encoding="utf-8")

        self.assertIn("Ipv4Addr::LOCALHOST", source)
        self.assertIn("TcpListener::bind", source)
        self.assertIn('"mode": "authorization_header_file"', config)
        self.assertIn('"dashboard": {"url": state.dashboard_url()}', config)
        self.assertIn("0o600", config)

    def test_readme_exposes_one_cli_control_surface(self) -> None:
        source = README.read_text(encoding="utf-8")

        self.assertIn("abyss deploy-local start", source)
        self.assertIn("abyss deploy-local status", source)
        self.assertIn("abyss deploy-local stop", source)
        self.assertIn("abyss run -- codex", source)
        self.assertNotIn("abyss-local", source)


if __name__ == "__main__":
    unittest.main()
