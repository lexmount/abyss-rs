"""Synchronous client for the loopback broker REST management API."""

import ipaddress
import json
from pathlib import Path
from typing import Any, Optional, TypeVar, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin, urlparse
from urllib.request import ProxyHandler, Request, build_opener

from .types import (
    BrokerLogRequest,
    BrokerLogResponse,
    DiagnosticsSnapshot,
    HealthResponse,
    HooksConfig,
    MitmConfig,
    NetworkObservationsResponse,
    ProxyStatus,
    TrafficSnapshot,
)

DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_ERROR_BODY_BYTES = 16 * 1024
ResponseType = TypeVar("ResponseType")


class BrokerApiError(RuntimeError):
    """Non-success response returned by the broker."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"broker REST request failed with HTTP {status}: {message}")
        self.status = status
        self.message = message


class BrokerTransportError(RuntimeError):
    """Transport failure before a broker response was available."""


class BrokerClient:
    """Synchronous client for local broker management operations."""

    def __init__(
        self,
        base_url: str,
        bearer_token: Optional[str] = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self._base_url = _normalized_base_url(base_url)
        self._bearer_token = bearer_token
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than zero")
        self._timeout_seconds = timeout_seconds
        self._opener = build_opener(ProxyHandler({}))

    @classmethod
    def from_startup_info(cls, path: str) -> "BrokerClient":
        """Discover the endpoint and bearer token from broker startup information."""

        startup_path = Path(path)
        startup = json.loads(startup_path.read_text(encoding="utf-8"))
        if not isinstance(startup, dict):
            raise TypeError("broker startup info must be an object")
        api_addr = startup.get("api_addr")
        token_path = startup.get("auth_token_file")
        if not isinstance(api_addr, str) or not isinstance(token_path, str):
            raise TypeError("broker startup info is missing REST discovery fields")
        token = Path(token_path).read_text(encoding="utf-8").strip()
        return cls(base_url=f"http://{api_addr}", bearer_token=token)

    def get_health(self) -> HealthResponse:
        return self._request("healthz", HealthResponse, protected=False)

    def get_proxy_status(self) -> ProxyStatus:
        return self._request("v1/proxy/status", ProxyStatus, protected=False)

    def get_mitm_config(self) -> MitmConfig:
        return self._request("v1/mitm/config", MitmConfig)

    def update_mitm_config(self, config: MitmConfig) -> MitmConfig:
        return self._request("v1/mitm/config", MitmConfig, method="PUT", body=config)

    def get_hooks_config(self) -> HooksConfig:
        return self._request("v1/hooks/config", HooksConfig)

    def update_hooks_config(self, config: HooksConfig) -> HooksConfig:
        return self._request("v1/hooks/config", HooksConfig, method="PUT", body=config)

    def collect_broker_logs(self, request: Optional[BrokerLogRequest] = None) -> BrokerLogResponse:
        return self._request(
            "v1/support/logs/broker",
            BrokerLogResponse,
            method="POST",
            body=request or {},
        )

    def get_diagnostics(self) -> DiagnosticsSnapshot:
        return self._request("v1/support/diagnostics", DiagnosticsSnapshot)

    def get_network_observations(self, limit: Optional[int] = None) -> NetworkObservationsResponse:
        if limit is not None and (isinstance(limit, bool) or not 1 <= limit <= 1000):
            raise ValueError("network observation limit must be between 1 and 1000")
        query = "" if limit is None else f"?{urlencode({'limit': limit})}"
        return self._request(f"v1/network/observations{query}", NetworkObservationsResponse)

    def get_traffic_snapshot(self) -> TrafficSnapshot:
        return self._request("v1/traffic/snapshot", TrafficSnapshot)

    def shutdown(self) -> ProxyStatus:
        return self._request("v1/broker/shutdown", ProxyStatus, method="POST")

    def _request(
        self,
        path: str,
        response_type: type[ResponseType],
        *,
        protected: bool = True,
        method: str = "GET",
        body: Optional[object] = None,
    ) -> ResponseType:
        del response_type  # Runtime TypedDict classes cannot validate values.
        headers = {"Accept": "application/json"}
        if protected and self._bearer_token is not None:
            headers["Authorization"] = f"Bearer {self._bearer_token}"
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body, separators=(",", ":")).encode("utf-8")
        request = Request(
            urljoin(self._base_url, path),
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                payload = response.read()
        except HTTPError as error:
            payload = error.read(MAX_ERROR_BODY_BYTES)
            raise BrokerApiError(error.code, _error_message(payload)) from error
        except URLError as error:
            raise BrokerTransportError(f"broker REST transport failed: {error}") from error
        decoded = json.loads(payload)
        if not isinstance(decoded, dict):
            raise TypeError("broker REST response must be a JSON object")
        return cast(ResponseType, decoded)


def _normalized_base_url(base_url: str) -> str:
    value = base_url.strip()
    parsed = urlparse(value)
    if parsed.scheme != "http" or not parsed.netloc or not _is_loopback_host(parsed.hostname):
        raise ValueError("base_url must use HTTP and a loopback host")
    return value.rstrip("/") + "/"


def _is_loopback_host(hostname: Optional[str]) -> bool:
    if hostname is None:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _error_message(payload: bytes) -> str:
    text = payload.decode("utf-8", errors="replace")
    try:
        decoded: Any = json.loads(text)
    except json.JSONDecodeError:
        return text
    if isinstance(decoded, dict) and isinstance(decoded.get("error"), str):
        return cast(str, decoded["error"])
    return text
