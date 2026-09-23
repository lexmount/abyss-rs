"""Exercise release rejection and recovery without uploading any crates."""

import copy
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError


SCRIPT = Path(__file__).resolve().parents[1] / "ci/publish_crates.py"
SPEC = importlib.util.spec_from_file_location("publish_crates", SCRIPT)
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def sample_metadata():
    packages = []
    for name in release.PACKAGES:
        packages.append({
            "id": name, "name": name, "version": "1.0.0", "publish": ["crates-io"],
            "description": "A public component", "readme": "README.md", "dependencies": [],
        })
    dependencies = {"abyss-broker": "abyss-agent-hook", "abyss-sdk": "abyss-plugin-protocol"}
    for package in packages:
        if dependency := dependencies.get(package["name"]):
            package["dependencies"] = [{
                "name": dependency, "kind": None,
                "path": f"/workspace/crates/{dependency}", "req": "^1.0.0", "source": None,
            }]
    packages.append({"id": "abyss-cli", "name": "abyss-cli", "publish": []})
    return {"packages": packages, "workspace_members": [p["id"] for p in packages]}


class ReleaseValidationTests(unittest.TestCase):
    def setUp(self):
        self.workspace = {"workspace": {"package": {"version": "1.0.0"}}}
        self.metadata = sample_metadata()

    def validate(self, tag="v1.0.0"):
        return release.validate_release(self.workspace, self.metadata, tag)

    def test_accepts_complete_broker_and_sdk_release(self):
        self.assertEqual(self.validate(), "1.0.0")
        self.assertEqual(self.validate(tag=None), "1.0.0")

    def test_rejects_wrong_or_malformed_tag(self):
        for tag in ("1.0.0", "v2.0.0", "v1.0.0-extra", "v1.0.0; echo unexpected"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "must equal"):
                self.validate(tag)

    def test_rejects_accidental_cli_publication(self):
        self.metadata["packages"][-1]["publish"] = None
        with self.assertRaisesRegex(ValueError, "must be exactly"):
            self.validate()

    def test_rejects_package_version_drift(self):
        self.metadata["packages"][0]["version"] = "1.0.1"
        with self.assertRaisesRegex(ValueError, "must use version"):
            self.validate()

    def test_rejects_unpublished_or_unversioned_dependency(self):
        dependency = self.metadata["packages"][-2]["dependencies"][0]
        for field, value in (("name", "abyss-cli"), ("req", "*"), ("req", "^0.9.0")):
            original = copy.deepcopy(dependency)
            dependency[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                self.validate()
            dependency.update(original)

    def test_rejects_dependency_published_after_consumer(self):
        self.metadata["packages"][0]["dependencies"] = [{
            "name": "abyss-broker", "kind": "build", "path": "/broker", "req": "^1.0.0",
        }]
        with self.assertRaisesRegex(ValueError, "unordered dependency"):
            self.validate()

    def test_rejects_git_dependency(self):
        self.metadata["packages"][0]["dependencies"] = [{
            "name": "external", "source": "git+https://example.invalid/repo", "kind": None,
        }]
        with self.assertRaisesRegex(ValueError, "git dependencies"):
            self.validate()


class RegistryTests(unittest.TestCase):
    def test_checks_exact_version_and_yank_status(self):
        for version, yanked, expected in (("1.0.0", False, True), ("0.9.0", False, False)):
            body = f'{{"vers":"{version}","yanked":{str(yanked).lower()}}}\n'.encode()
            with self.subTest(version=version), patch.object(release, "urlopen", return_value=io.BytesIO(body)):
                self.assertEqual(release.published_version("abyss-broker", "1.0.0"), expected)
        with patch.object(release, "urlopen", return_value=io.BytesIO(b'{"vers":"1.0.0","yanked":true}\n')):
            with self.assertRaisesRegex(ValueError, "yanked"):
                release.published_version("abyss-broker", "1.0.0")

    def test_only_404_is_treated_as_missing(self):
        for status in (404, 403, 429, 500):
            error = HTTPError("https://index.crates.io/test", status, "test", {}, None)
            with self.subTest(status=status), patch.object(release, "urlopen", side_effect=error):
                if status == 404:
                    self.assertFalse(release.published_version("abyss-broker", "1.0.0"))
                else:
                    with self.assertRaises(HTTPError):
                        release.published_version("abyss-broker", "1.0.0")

    def test_network_failure_stops_check(self):
        with patch.object(release, "urlopen", side_effect=URLError("offline")):
            with self.assertRaises(URLError):
                release.published_version("abyss-broker", "1.0.0")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(release.os.environ, {"CARGO_REGISTRY_TOKEN": "test-token"})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    @patch.object(release.subprocess, "run")
    @patch.object(release.subprocess, "check_output", return_value=b"")
    @patch.object(release, "published_version", side_effect=lambda name, _version: name in release.PACKAGES[:2])
    def test_partial_release_resumes_in_dependency_order(self, _index, _git, run):
        release.publish_release("1.0.0")
        self.assertEqual([call.args[0][-1] for call in run.call_args_list], list(release.PACKAGES[2:]))
        for call in run.call_args_list:
            self.assertNotIn("test-token", call.args[0])
            self.assertNotIn("--no-verify", call.args[0])

    @patch.object(release.subprocess, "run")
    @patch.object(release.subprocess, "check_output", return_value=b"")
    @patch.object(release, "published_version", side_effect=lambda name, _version: name != "abyss-sdk")
    def test_only_publishes_sdk_when_other_crates_already_exist(self, _index, _git, run):
        release.publish_release("1.0.0")
        run.assert_called_once_with(
            ["cargo", "publish", "--locked", "--registry", "crates-io", "--package", "abyss-sdk"],
            cwd=release.ROOT, check=True,
        )

    @patch.object(release.subprocess, "run", side_effect=subprocess.CalledProcessError(101, "cargo"))
    @patch.object(release.subprocess, "check_output", return_value=b"")
    @patch.object(release, "published_version", return_value=False)
    def test_publish_failure_stops_before_dependents(self, _index, _git, run):
        with self.assertRaises(subprocess.CalledProcessError):
            release.publish_release("1.0.0")
        self.assertEqual(run.call_count, 1)

    @patch.object(release.subprocess, "run")
    @patch.object(release.subprocess, "check_output", return_value=b"")
    @patch.object(release, "published_version", side_effect=[False, False, URLError("offline")])
    def test_registry_failure_is_detected_before_first_upload(self, _index, _git, run):
        with self.assertRaises(URLError):
            release.publish_release("1.0.0")
        run.assert_not_called()

    @patch.object(release.subprocess, "run")
    def test_requires_token_and_clean_checkout(self, run):
        with patch.dict(release.os.environ, {"CARGO_REGISTRY_TOKEN": ""}):
            with self.assertRaisesRegex(ValueError, "TOKEN is required"):
                release.publish_release("1.0.0")
        with patch.object(release.subprocess, "check_output", return_value=b" M Cargo.toml"):
            with self.assertRaisesRegex(ValueError, "clean Git checkout"):
                release.publish_release("1.0.0")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
