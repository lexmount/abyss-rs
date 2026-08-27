"""Language-neutral broker REST OpenAPI contract checks."""

import unittest
from pathlib import Path
from typing import Any

import yaml

SPEC_PATH = Path(__file__).resolve().parents[3] / "specs" / "broker-rest-api" / "openapi.yaml"
EXPECTED_OPERATIONS = {
    "/healthz": {"get": "getHealth"},
    "/v1/proxy/status": {"get": "getProxyStatus"},
    "/v1/mitm/config": {
        "get": "getMitmConfig",
        "put": "updateMitmConfig",
    },
    "/v1/hooks/config": {
        "get": "getHooksConfig",
        "put": "updateHooksConfig",
    },
    "/v1/support/logs/broker": {"post": "collectBrokerLogs"},
    "/v1/support/diagnostics": {"get": "getDiagnostics"},
    "/v1/network/observations": {"get": "getNetworkObservations"},
    "/v1/traffic/snapshot": {"get": "getTrafficSnapshot"},
    "/v1/broker/shutdown": {"post": "shutdownBroker"},
}


class BrokerRestOpenApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.document = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))

    def test_published_operations_match_the_broker_surface(self) -> None:
        self.assertEqual(self.document["openapi"], "3.1.0")
        paths = self.document["paths"]
        self.assertEqual(set(paths), set(EXPECTED_OPERATIONS))
        for path, operations in EXPECTED_OPERATIONS.items():
            for method, operation_id in operations.items():
                self.assertEqual(paths[path][method]["operationId"], operation_id)

    def test_public_routes_override_bearer_security(self) -> None:
        self.assertEqual(self.document["security"], [{"localBearer": []}])
        self.assertEqual(self.document["paths"]["/healthz"]["get"]["security"], [])
        self.assertEqual(self.document["paths"]["/v1/proxy/status"]["get"]["security"], [])

    def test_every_local_reference_resolves(self) -> None:
        for reference in _references(self.document):
            self.assertTrue(reference.startswith("#/"), f"non-local reference: {reference}")
            resolved: Any = self.document
            for encoded_part in reference[2:].split("/"):
                part = encoded_part.replace("~1", "/").replace("~0", "~")
                self.assertIsInstance(resolved, dict)
                self.assertIn(part, resolved)
                resolved = resolved[part]


def _references(value: Any) -> list[str]:
    if isinstance(value, dict):
        found = [value["$ref"]] if isinstance(value.get("$ref"), str) else []
        for nested in value.values():
            found.extend(_references(nested))
        return found
    if isinstance(value, list):
        found = []
        for nested in value:
            found.extend(_references(nested))
        return found
    return []


if __name__ == "__main__":
    unittest.main()
