"""Type hints for the stable broker REST request and response contract."""

from typing import Any, Literal, Optional, TypedDict


class HealthResponse(TypedDict):
    service: Literal["abyss-broker"]
    status: Literal["ok"]


class _IngressStatusRequired(TypedDict):
    source: Literal["explicit_http", "macos_network_extension", "windows_wfp"]
    listen_addr: Optional[str]


class IngressStatus(_IngressStatusRequired, total=False):
    socket_path: str


class _ProxyStatusRequired(TypedDict):
    lifecycle: Literal["running", "stopped"]
    process_id: int
    mode: Optional[Literal["explicit", "transparent"]]
    ingresses: list[IngressStatus]
    listen_addr: Optional[str]


class ProxyStatus(_ProxyStatusRequired, total=False):
    socket_path: str


class _TlsDecryptionRuleRequired(TypedDict):
    id: str
    enabled: bool
    action: Literal["intercept", "passthrough"]
    destination_hosts: list[str]


class TlsDecryptionRule(_TlsDecryptionRuleRequired, total=False):
    process_names: list[str]
    application_ids: list[str]


class TlsDecryptionPolicy(TypedDict):
    default_action: Literal["intercept", "passthrough"]
    missing_sni_action: Optional[Literal["intercept", "passthrough"]]
    rules: list[TlsDecryptionRule]


class MitmConfig(TypedDict):
    tls_decryption: TlsDecryptionPolicy


class HarnessUsageContentConfig(TypedDict):
    token_usage: bool
    conversation_text: bool
    tool_calls: bool
    images: bool


class HarnessMatcherConfig(TypedDict, total=False):
    process_names: list[str]
    application_ids: list[str]


class HarnessConfig(TypedDict, total=False):
    enabled: bool
    content: HarnessUsageContentConfig
    matchers: list[HarnessMatcherConfig]


class HarnessUsageConfig(TypedDict):
    content: HarnessUsageContentConfig
    harnesses: dict[str, HarnessConfig]


class HarnessUsageHookConfig(TypedDict):
    enabled: bool
    config: HarnessUsageConfig


class HooksConfig(TypedDict):
    harness_usage: HarnessUsageHookConfig


class BrokerLogRequest(TypedDict, total=False):
    max_bytes_per_file: int


class BrokerLogFile(TypedDict):
    name: str
    content: str
    truncated: bool
    original_size: int


class BrokerLogError(TypedDict):
    name: str
    error: str


class BrokerLogResponse(TypedDict):
    files: list[BrokerLogFile]
    errors: list[BrokerLogError]


class TrafficSnapshot(TypedDict):
    sampled_at_unix_ms: int
    upload_bytes_per_second: int
    download_bytes_per_second: int
    total_upload_bytes: int
    total_download_bytes: int
    active_flows: list[dict[str, Any]]


class DiagnosticsSnapshot(TypedDict):
    schema_version: int
    collected_at_unix_ms: int
    broker: dict[str, Any]
    proxy: ProxyStatus
    flow: dict[str, Any]


class NetworkObservationsResponse(TypedDict):
    schema_version: Literal[1]
    broker_started_at_unix_ms: int
    observations: list[dict[str, Any]]
