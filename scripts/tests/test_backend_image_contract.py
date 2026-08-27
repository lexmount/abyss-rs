#!/usr/bin/env python3
"""Regression tests for the external Backend runtime boundary."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
IMAGE_FILE = REPO_ROOT / "scripts" / "ci" / "abyss-backend-image.txt"
IMAGE_PATTERN = re.compile(
    r"docker\.io/lexmount/abyss-backend@sha256:[0-9a-f]{64}"
)
CONSUMERS = (
    REPO_ROOT / "scripts" / "blackbox_codex_usage_upload.sh",
    REPO_ROOT / "scripts" / "blackbox_claude_code_usage_upload.sh",
    REPO_ROOT / "scripts" / "agent_e2e_ci" / "config.py",
)
AUTHENTICATED_CONSUMERS = CONSUMERS[:2]


class BackendImageContractTests(unittest.TestCase):
    def test_default_image_is_public_and_digest_pinned(self) -> None:
        image = IMAGE_FILE.read_text(encoding="utf-8").strip()
        self.assertIsNotNone(IMAGE_PATTERN.fullmatch(image))

    def test_endpoint_blackboxes_use_the_shared_pin_and_deployment_bearer(self) -> None:
        for path in CONSUMERS:
            with self.subTest(path=path.relative_to(REPO_ROOT)):
                source = path.read_text(encoding="utf-8")
                self.assertIn("abyss-backend-image.txt", source)
                self.assertNotIn("dockerfile/abyss-backend.Dockerfile", source)
                self.assertNotIn("native_auth_sessions", source)
                self.assertNotIn("app_users", source)

        for path in AUTHENTICATED_CONSUMERS:
            source = path.read_text(encoding="utf-8")
            self.assertIn("ABYSS_BACKEND_API_TOKEN_SHA256", source)

    def test_backend_source_and_service_deployment_are_not_owned_here(self) -> None:
        backend_root = REPO_ROOT / "crates" / "abyss-backend"
        self.assertFalse(any(path.is_file() for path in backend_root.rglob("*")))
        self.assertFalse(
            (REPO_ROOT / "dockerfile" / "abyss-backend.Dockerfile").exists()
        )
        deployment_root = REPO_ROOT / "k8s" / "apps" / "abyss-backend"
        self.assertFalse(any(path.is_file() for path in deployment_root.rglob("*")))


if __name__ == "__main__":
    unittest.main()
