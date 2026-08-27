"""Isolated PostgreSQL, Backend, CA, and explicit-proxy broker lifecycle."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

from .config import RuntimeConfig
from .process import CommandRunner, LoopbackHttpClient, OrchestrationError, ProcessGroup


class _PortReservation:
    """Keeps one loopback port unavailable until its service is ready to launch."""

    def __init__(self) -> None:
        self._listener: socket.socket | None = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.bind(("127.0.0.1", 0))
        self.port = int(self._listener.getsockname()[1])

    def release(self) -> None:
        listener = self._listener
        if listener is None:
            return
        self._listener = None
        listener.close()


class TestStack:
    """Owns every mutable resource created for one Agent E2E CI run."""

    def __init__(
        self,
        config: RuntimeConfig,
        commands: CommandRunner,
        http: LoopbackHttpClient,
    ) -> None:
        self.config = config
        self.commands = commands
        self.http = http
        resource_id = config.run_id.lower()[-52:]
        self.network_name = f"abyss-agent-e2e-{resource_id}"
        self.postgres_container = f"abyss-agent-e2e-postgres-{resource_id}"
        self.backend_container = f"abyss-agent-e2e-backend-{resource_id}"
        self._backend_port_reservation = _PortReservation()
        self._proxy_port_reservation = _PortReservation()
        self.backend_port = self._backend_port_reservation.port
        self.proxy_port = self._proxy_port_reservation.port
        self.backend_base_url = f"http://127.0.0.1:{self.backend_port}"
        self.broker_base_url = ""
        self.proxy_url = f"http://127.0.0.1:{self.proxy_port}"
        self.native_token = secrets.token_hex(32)
        self.broker_token: str | None = None
        self.broker_process: subprocess.Popen[bytes] | None = None
        self.broker_log_handle: Any | None = None
        self.delivery_process: subprocess.Popen[bytes] | None = None
        self.delivery_log_handle: Any | None = None
        self.network_created = False
        self.postgres_started = False
        self.backend_started = False
        self.prepared = False

    @property
    def ca_directory(self) -> Path:
        return self.config.runtime_root / "ca"

    @property
    def ca_certificate(self) -> Path:
        return self.ca_directory / "abyss-root-ca.pem"

    @property
    def broker_home(self) -> Path:
        return self.config.runtime_root / "broker-home"

    @property
    def runtime_policy_path(self) -> Path:
        return self.broker_home / "runtime-policy.toml"

    @property
    def broker_startup_info_path(self) -> Path:
        return self.broker_home / "runtime" / "startup-info.json"

    @property
    def spool_path(self) -> Path:
        return self.broker_home / "delivery" / "failed-events.jsonl"

    @property
    def broker_log_path(self) -> Path:
        return self.config.runtime_root / "logs" / "broker-stdio.log"

    @property
    def delivery_log_path(self) -> Path:
        return self.config.runtime_root / "logs" / "delivery-plugin.log"

    def start(self) -> None:
        self._prepare_directories()
        self._pull_backend()
        self._build_broker()
        self._write_ca()
        self._create_network()
        self._start_postgres()
        self._start_backend()
        self._write_broker_config()
        self._write_delivery_config()
        self._start_broker()
        self._start_delivery_plugin()

    def health_snapshot(self) -> dict[str, Any]:
        snapshot: dict[str, Any] = {
            "backend_url": self.backend_base_url,
            "broker_url": self.broker_base_url,
            "proxy_url": self.proxy_url,
        }
        snapshot["delivery_plugin"] = {
            "running": self.delivery_process is not None
            and self.delivery_process.poll() is None
        }
        for name, url, bearer in (
            ("backend", f"{self.backend_base_url}/readyz", None),
            ("broker", f"{self.broker_base_url}/healthz", None),
            (
                "proxy",
                f"{self.broker_base_url}/v1/proxy/status",
                self.broker_token,
            ),
        ):
            try:
                snapshot[name] = self.http.json(url, bearer=bearer)
            except OrchestrationError as error:
                snapshot[name] = {"error": str(error)}
        return snapshot

    def collect_service_logs(self) -> None:
        if not self.prepared:
            return
        logs = self.config.runtime_root / "logs"
        logs.mkdir(mode=0o700, parents=True, exist_ok=True)
        for started, container, filename in (
            (self.backend_started, self.backend_container, "backend-container.log"),
            (self.postgres_started, self.postgres_container, "postgres-container.log"),
        ):
            if not started:
                continue
            result = self.commands.run(
                ["docker", "logs", "--tail", "500", container],
                check=False,
            )
            (logs / filename).write_text(
                result.stdout + result.stderr,
                encoding="utf-8",
            )

    def flush_broker_log(self) -> None:
        """Makes broker diagnostics visible before the semantic judge runs."""
        if self.broker_log_handle is not None:
            self.broker_log_handle.flush()
        if self.delivery_log_handle is not None:
            self.delivery_log_handle.flush()

    def stop(self) -> None:
        self._release_port_reservations()
        self.collect_service_logs()
        self._stop_delivery_plugin()
        self._stop_broker()
        if self.backend_started:
            self.commands.run(
                ["docker", "rm", "--force", self.backend_container],
                check=False,
            )
            self.backend_started = False
        if self.postgres_started:
            self.commands.run(
                ["docker", "rm", "--force", self.postgres_container],
                check=False,
            )
            self.postgres_started = False
        if self.network_created:
            self.commands.run(
                ["docker", "network", "rm", self.network_name],
                check=False,
            )
            self.network_created = False
        self.native_token = ""
        self.broker_token = None

    def _prepare_directories(self) -> None:
        root = self.config.runtime_root
        if root.exists():
            raise OrchestrationError(f"runtime root already exists: {root}")
        root.mkdir(mode=0o700, parents=True)
        for path in (
            self.ca_directory,
            self.config.artifact_root,
            root / "coordinator",
            root / "logs",
            root / "secrets",
            root / "tmp",
            self.broker_home,
        ):
            path.mkdir(mode=0o700, parents=True)
        self.prepared = True
        token_path = root / "secrets" / "native-token"
        token_path.write_text(self.native_token, encoding="utf-8")
        token_path.chmod(0o600)
        delivery_auth_path = root / "secrets" / "delivery-authorization"
        delivery_auth_path.write_text(
            f"Bearer {self.native_token}\n", encoding="utf-8"
        )
        delivery_auth_path.chmod(0o600)

    def _pull_backend(self) -> None:
        self.commands.run(
            [
                "docker",
                "pull",
                "--platform",
                self.config.backend_platform,
                self.config.backend_image,
            ],
            timeout=600,
            label="Backend image pull",
        )

    def _build_broker(self) -> None:
        self.commands.run(
            [
                "cargo",
                "build",
                "--locked",
                "--package",
                "abyss-broker",
                "--package",
                "abyss-delivery-plugin",
            ],
            cwd=self.config.repo_root,
            timeout=1_800,
            label="abyss-broker build",
        )

    def _write_ca(self) -> None:
        openssl_config = self.config.runtime_root / "root-openssl.cnf"
        openssl_config.write_text(
            "\n".join(
                (
                    "[req]",
                    "distinguished_name = dn",
                    "x509_extensions = v3_ca",
                    "prompt = no",
                    "",
                    "[dn]",
                    f"CN = Abyss Agent E2E {self.config.run_id}",
                    "",
                    "[v3_ca]",
                    "basicConstraints = critical, CA:true",
                    "keyUsage = critical, keyCertSign, cRLSign",
                    "subjectKeyIdentifier = hash",
                    "authorityKeyIdentifier = keyid:always",
                    "",
                )
            ),
            encoding="utf-8",
        )
        private_key = self.ca_directory / "abyss-root-ca-key.pem"
        self.commands.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-sha256",
                "-config",
                str(openssl_config),
                "-keyout",
                str(private_key),
                "-out",
                str(self.ca_certificate),
            ],
            label="temporary CA generation",
        )
        self.commands.run(
            [
                "openssl",
                "x509",
                "-in",
                str(self.ca_certificate),
                "-outform",
                "DER",
                "-out",
                str(self.ca_directory / "abyss-root-ca.der"),
            ],
            label="temporary CA DER conversion",
        )
        private_key.chmod(0o600)

    def _create_network(self) -> None:
        self.commands.run(
            [
                "docker",
                "network",
                "create",
                "--label",
                f"com.lexmount.abyss.agent-e2e-run={self.config.run_id}",
                self.network_name,
            ],
            label="Docker network creation",
        )
        self.network_created = True

    def _start_postgres(self) -> None:
        self.commands.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                self.postgres_container,
                "--network",
                self.network_name,
                "--label",
                f"com.lexmount.abyss.agent-e2e-run={self.config.run_id}",
                "--env",
                "POSTGRES_USER=abyss",
                "--env",
                "POSTGRES_PASSWORD=abyss",
                "--env",
                "POSTGRES_DB=abyss",
                self.config.postgres_image,
            ],
            label="PostgreSQL container start",
        )
        self.postgres_started = True
        deadline = time.monotonic() + self.config.startup_timeout_seconds
        while time.monotonic() < deadline:
            result = self.commands.run(
                [
                    "docker",
                    "exec",
                    self.postgres_container,
                    "pg_isready",
                    "-U",
                    "abyss",
                    "-d",
                    "abyss",
                ],
                check=False,
            )
            if result.returncode == 0:
                return
            time.sleep(1)
        raise OrchestrationError("PostgreSQL did not become ready")

    def _start_backend(self) -> None:
        database_url = (
            f"postgres://abyss:abyss@{self.postgres_container}:5432/abyss?sslmode=disable"
        )
        self._backend_port_reservation.release()
        self.commands.run(
            [
                "docker",
                "run",
                "--platform",
                self.config.backend_platform,
                "--detach",
                "--name",
                self.backend_container,
                "--network",
                self.network_name,
                "--label",
                f"com.lexmount.abyss.agent-e2e-run={self.config.run_id}",
                "--publish",
                f"127.0.0.1:{self.backend_port}:8080",
                "--env",
                "ABYSS_BACKEND_ADDR=0.0.0.0:8080",
                "--env",
                "ABYSS_BACKEND_ENV=blackbox",
                "--env",
                "ABYSS_BACKEND_API_TOKEN_SHA256="
                + hashlib.sha256(self.native_token.encode("utf-8")).hexdigest(),
                "--env",
                "ABYSS_BACKEND_BLACKBOX_ALLOW_NON_LOOPBACK=true",
                "--env",
                f"ABYSS_BACKEND_DATABASE_URL={database_url}",
                "--env",
                "ABYSS_BACKEND_RUN_MIGRATIONS=true",
                self.config.backend_image,
            ],
            label="Backend container start",
        )
        self.backend_started = True
        self.http.wait_until(
            lambda: self.http.json(f"{self.backend_base_url}/readyz").get("status") == "ok",
            timeout_seconds=self.config.startup_timeout_seconds,
            description="abyss-backend readiness",
        )

    def _write_broker_config(self) -> None:
        broker_config = f"""schema_version = 1

[devtools]
log_level = "info"
performance_trace = false
log_location = {json.dumps(str(self.config.runtime_root / "logs" / "broker"))}

[ca]
path = {json.dumps(str(self.ca_directory))}

[proxy]
mode = "explicit"
listen_addr = "127.0.0.1:{self.proxy_port}"
"""
        runtime_policy = """schema_version = 1

[mitm.tls_decryption]
default_action = "passthrough"
missing_sni_action = "passthrough"

[[mitm.tls_decryption.rules]]
id = "agent-e2e-openai"
action = "intercept"
destination_hosts = ["openai.com", "*.openai.com", "chatgpt.com", "*.chatgpt.com"]

[hooks.harness_usage]
enabled = true

[hooks.harness_usage.config.content]
token_usage = true
conversation_text = true
tool_calls = true
images = true

[hooks.harness_usage.config.harnesses.codex]
enabled = true

[hooks.harness_usage.config.harnesses.codex.content]
token_usage = true
conversation_text = true
tool_calls = true
images = true
"""
        path = self.config.runtime_root / "broker-config.toml"
        path.write_text(broker_config, encoding="utf-8")
        self.runtime_policy_path.write_text(runtime_policy, encoding="utf-8")

    def _write_delivery_config(self) -> None:
        config = {
            "schema_version": 1,
            "product": {"kind": "cli"},
            "delivery_worker": {
                "plugin_id": "lexmount.abyss.agent-e2e-delivery",
                "delivery": {
                    "endpoint": f"{self.backend_base_url}/v1/agent-usage/events",
                    "spool_enabled": True,
                    "spool_path": str(self.spool_path),
                },
                "authentication": {
                    "mode": "authorization_header_file",
                    "path": str(
                        self.config.runtime_root / "secrets" / "delivery-authorization"
                    ),
                },
            },
        }
        path = self.config.runtime_root / "product-config.json"
        path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")

    def _start_broker(self) -> None:
        token_file = self.config.runtime_root / "secrets" / "broker-control-token"
        target_root = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        if not target_root.is_absolute():
            target_root = self.config.repo_root / target_root
        broker_binary = target_root / "debug" / "abyss-broker"
        environment = CommandRunner.child_environment(
            {
                "ABYSS_HOME": str(self.broker_home),
                "TMPDIR": str(self.config.runtime_root / "tmp"),
            }
        )
        for name in (
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
        ):
            environment.pop(name, None)
        self.broker_log_handle = self.broker_log_path.open("wb")
        self._proxy_port_reservation.release()
        self.broker_process = subprocess.Popen(
            [
                str(broker_binary),
                "--api",
                "127.0.0.1:0",
                "--config",
                str(self.config.runtime_root / "broker-config.toml"),
                "--auth-token-file",
                str(token_file),
                "--startup-info-file",
                str(self.broker_startup_info_path),
            ],
            cwd=self.config.repo_root,
            env=environment,
            stdout=self.broker_log_handle,
            stderr=subprocess.STDOUT,
            **ProcessGroup.popen_options(),
        )

        def broker_ready() -> bool:
            if self.broker_process is not None and self.broker_process.poll() is not None:
                raise OrchestrationError("abyss-broker exited before becoming ready")
            if not token_file.is_file() or not self.broker_startup_info_path.is_file():
                return False
            startup_info = json.loads(
                self.broker_startup_info_path.read_text(encoding="utf-8")
            )
            api_addr = startup_info.get("api_addr")
            if not isinstance(api_addr, str):
                return False
            host, separator, port = api_addr.rpartition(":")
            if separator != ":" or host != "127.0.0.1" or not port.isdigit():
                raise OrchestrationError("broker startup info contains an invalid API address")
            if int(port) == 0:
                raise OrchestrationError("broker startup info contains an unbound API port")
            self.broker_base_url = f"http://{api_addr}"
            health = self.http.json(f"{self.broker_base_url}/healthz")
            return health.get("status") == "ok"

        self.http.wait_until(
            broker_ready,
            timeout_seconds=self.config.startup_timeout_seconds,
            description="abyss-broker readiness",
        )
        self.broker_token = token_file.read_text(encoding="utf-8").strip()
        if not self.broker_token:
            raise OrchestrationError("abyss-broker control token file is empty")
        self._assert_runtime_policy_loaded()
        status = self.http.json(
            f"{self.broker_base_url}/v1/proxy/status",
            bearer=self.broker_token,
        )
        listener = f"127.0.0.1:{self.proxy_port}"
        ingresses = status.get("ingresses")
        listener_found = isinstance(ingresses, list) and any(
            isinstance(ingress, dict)
            and ingress.get("source") == "explicit_http"
            and ingress.get("listen_addr") == listener
            for ingress in ingresses
        )
        status_matches = status.get("lifecycle") == "running" and status.get("mode") == "explicit"
        if not status_matches or not listener_found:
            raise OrchestrationError("broker did not report the expected explicit proxy listener")

    def _start_delivery_plugin(self) -> None:
        target_root = Path(os.environ.get("CARGO_TARGET_DIR", "target"))
        if not target_root.is_absolute():
            target_root = self.config.repo_root / target_root
        delivery_binary = target_root / "debug" / "abyss-delivery-plugin"
        environment = CommandRunner.child_environment(
            {
                "ABYSS_HOME": str(self.broker_home),
                "ABYSS_BROKER_STARTUP_INFO": str(self.broker_startup_info_path),
            }
        )
        for name in (
            "ALL_PROXY",
            "all_proxy",
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
        ):
            environment.pop(name, None)
        self.delivery_log_handle = self.delivery_log_path.open("wb")
        self.delivery_process = subprocess.Popen(
            [
                str(delivery_binary),
                "--config",
                str(self.config.runtime_root / "product-config.json"),
            ],
            cwd=self.config.repo_root,
            env=environment,
            stdout=self.delivery_log_handle,
            stderr=subprocess.STDOUT,
            **ProcessGroup.popen_options(),
        )
        time.sleep(1)
        if self.delivery_process.poll() is not None:
            raise OrchestrationError(
                "abyss-delivery-plugin exited before Agent traffic started"
            )

    def _assert_runtime_policy_loaded(self) -> None:
        if self.broker_token is None:
            raise OrchestrationError("broker control token is unavailable")
        mitm = self.http.json(
            f"{self.broker_base_url}/v1/mitm/config",
            bearer=self.broker_token,
        )
        tls_decryption = mitm.get("tls_decryption")
        rules = tls_decryption.get("rules") if isinstance(tls_decryption, dict) else None
        mitm_loaded = isinstance(rules, list) and any(
            isinstance(rule, dict)
            and rule.get("id") == "agent-e2e-openai"
            and rule.get("action") == "intercept"
            for rule in rules
        )
        if not mitm_loaded:
            raise OrchestrationError(
                f"broker did not load MITM policy from {self.runtime_policy_path}"
            )

        hooks = self.http.json(
            f"{self.broker_base_url}/v1/hooks/config",
            bearer=self.broker_token,
        )
        harness_usage = hooks.get("harness_usage")
        hook_config = harness_usage.get("config") if isinstance(harness_usage, dict) else None
        harnesses = hook_config.get("harnesses") if isinstance(hook_config, dict) else None
        codex = harnesses.get("codex") if isinstance(harnesses, dict) else None
        if not (
            isinstance(harness_usage, dict)
            and harness_usage.get("enabled") is True
            and isinstance(codex, dict)
            and codex.get("enabled") is True
        ):
            raise OrchestrationError(
                f"broker did not load Hook policy from {self.runtime_policy_path}"
            )

    def _stop_delivery_plugin(self) -> None:
        process = self.delivery_process
        if process is None:
            return
        if process.poll() is None:
            ProcessGroup.request_stop(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ProcessGroup.force_stop(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self.delivery_process = None
        if self.delivery_log_handle is not None:
            self.delivery_log_handle.close()
            self.delivery_log_handle = None

    def _stop_broker(self) -> None:
        process = self.broker_process
        if process is None:
            return
        if process.poll() is None and self.broker_token:
            try:
                self.http.json(
                    f"{self.broker_base_url}/v1/broker/shutdown",
                    method="POST",
                    bearer=self.broker_token,
                    timeout=5,
                )
            except OrchestrationError:
                pass
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            ProcessGroup.request_stop(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                ProcessGroup.force_stop(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        self.broker_process = None
        if self.broker_log_handle is not None:
            self.broker_log_handle.close()
            self.broker_log_handle = None

    def _release_port_reservations(self) -> None:
        self._backend_port_reservation.release()
        self._proxy_port_reservation.release()
