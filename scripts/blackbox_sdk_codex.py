#!/usr/bin/env python3
"""Exercise three SDKs with real Codex -> broker -> OpenAI traffic.

The local HTTP probe only establishes plugin readiness. All test prompts are
sent by the actual Codex executable to api.openai.com through TLS interception.
Only sanitized SDK evidence is exported; temporary keys and raw logs are removed.
"""

import argparse
import contextlib
import http.client
import http.server
import json
import os
import signal
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY_REASON = "SDK black-box policy"


def child_environment():
    environment = dict(os.environ)
    for name in (
        "CODEX_API_KEY",
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    ):
        environment.pop(name, None)
    return environment


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def records(path):
    if not path.exists():
        return []
    # A writer may be in the middle of its last line; committed lines are complete.
    return [
        json.loads(line)
        for line in path.read_text().splitlines(keepends=True)
        if line.endswith("\n")
    ]


def wait_until(check, description, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {description}")


class Probe(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(204)
        self.end_headers()

    def log_message(self, *_args):
        pass


class Broker:
    def __init__(self, directory, cleanup):
        self.directory = directory
        home, ca = directory / "home", directory / "ca"
        home.mkdir()
        ca.mkdir()
        self.ca_file = ca / "abyss-root-ca.pem"
        openssl_config = directory / "openssl.cnf"
        openssl_config.write_text(
            "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n"
            "[dn]\nCN=Abyss SDK Codex Test\n[ca]\nbasicConstraints=critical,CA:true\n"
            "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
        )
        for arguments in (
            [
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
                str(ca / "abyss-root-ca-key.pem"),
                "-out",
                str(self.ca_file),
            ],
            [
                "x509",
                "-in",
                str(self.ca_file),
                "-outform",
                "DER",
                "-out",
                str(ca / "abyss-root-ca.der"),
            ],
        ):
            subprocess.run(
                ["openssl", *arguments],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        (ca / "abyss-root-ca-key.pem").chmod(0o600)
        config = directory / "broker-config.toml"
        config.write_text(
            'schema_version=1\n[devtools]\nlog_level="info"\n'
            f"log_location={json.dumps(str(directory / 'logs'))}\n"
            '[ca]\npath="ca"\n[proxy]\nmode="explicit"\nlisten_addr="127.0.0.1:0"\n'
        )
        (home / "runtime-policy.toml").write_text(
            'schema_version=1\n[mitm.tls_decryption]\ndefault_action="passthrough"\n'
            '[[mitm.tls_decryption.rules]]\nid="sdk-codex"\naction="intercept"\n'
            'destination_hosts=["api.openai.com", "127.0.0.1"]\n'
            "[hooks.harness_usage]\nenabled=true\n"
            "[hooks.harness_usage.config.content]\nconversation_text=true\ntoken_usage=true\n"
        )
        startup = directory / "startup.json"
        self.token_file = directory / "token"
        log = cleanup.enter_context((directory / "broker.log").open("w"))
        environment = child_environment()
        environment["ABYSS_HOME"] = str(home)
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
        self.process = subprocess.Popen(
            [
                str(target / "debug/abyss-broker"),
                "--api",
                "127.0.0.1:0",
                "--config",
                str(config),
                "--auth-token-file",
                str(self.token_file),
                "--startup-info-file",
                str(startup),
            ],
            cwd=ROOT,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        cleanup.callback(stop, self.process)

        def ready():
            assert self.process.poll() is None, "broker exited during startup"
            return startup.exists() and self.token_file.exists()

        wait_until(ready, "broker startup")
        info = json.loads(startup.read_text())
        self.endpoint, self.api = info["plugin_endpoint"], info["api_addr"]
        self.token = self.token_file.read_text().strip()
        address = self.api_request("GET", "/v1/proxy/status")["ingresses"][0][
            "listen_addr"
        ]
        self.proxy_url = f"http://{address}"
        self.address = address

    def api_request(self, method, path, timeout=5):
        connection = http.client.HTTPConnection(self.api, timeout=timeout)
        try:
            connection.request(
                method, path, headers={"Authorization": f"Bearer {self.token}"}
            )
            response = connection.getresponse()
            assert response.status == 200, f"broker API status {response.status}"
            return json.loads(response.read())
        finally:
            connection.close()

    def shutdown(self):
        # The broker permits existing connections to drain for ten seconds.
        self.api_request("POST", "/v1/broker/shutdown", timeout=15)
        assert self.process.wait(timeout=10) == 0, "broker shutdown failed"


def plugin_command(language):
    return {
        "rust": [
            "cargo",
            "test",
            "--locked",
            "--package",
            "abyss-sdk",
            "--test",
            "codex_inspection",
            "codex_inspection_plugin",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
        ],
        "typescript": ["node", "sdks/typescript/test/codex-inspection.mjs"],
        "python": ["python3", "sdks/python/tests/codex_inspection.py"],
    }[language]


def await_plugin(broker, process, evidence):
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Probe)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:

        def ready():
            assert process.poll() is None, "SDK plugin exited before readiness"
            connection = http.client.HTTPConnection(broker.address, timeout=5)
            try:
                connection.request(
                    "GET", f"http://127.0.0.1:{server.server_port}/__abyss_sdk_ready"
                )
                response = connection.getresponse()
                response.read()
                assert response.status == 204, "plugin readiness request failed"
            finally:
                connection.close()
            return any(row["kind"] == "ready" for row in records(evidence))

        wait_until(ready, "SDK inspection handler")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def run_codex(broker, directory, marker, model, api_key):
    directory.mkdir()
    codex_home = directory / "codex-home"
    codex_home.mkdir()
    environment = child_environment()
    environment.update(
        {
            "CODEX_HOME": str(codex_home),
            "CODEX_API_KEY": api_key,
            "HTTP_PROXY": broker.proxy_url,
            "HTTPS_PROXY": broker.proxy_url,
            "http_proxy": broker.proxy_url,
            "https_proxy": broker.proxy_url,
            "NO_PROXY": "localhost,127.0.0.1,::1",
            "no_proxy": "localhost,127.0.0.1,::1",
            "CODEX_CA_CERTIFICATE": str(broker.ca_file),
            "SSL_CERT_FILE": str(broker.ca_file),
        }
    )
    command = [
        "codex",
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--cd",
        str(directory),
        "--model",
        model,
        "--output-last-message",
        str(directory / "last-message.txt"),
        "-c",
        'model_provider="sdk_openai"',
        "-c",
        'model_providers.sdk_openai={name="OpenAI",base_url="https://api.openai.com/v1",env_key="CODEX_API_KEY",wire_api="responses",request_max_retries=0,stream_max_retries=0,supports_websockets=false}',
        "-c",
        'shell_environment_policy.inherit="none"',
        "--",
        "-",
    ]
    with subprocess.Popen(
        command,
        env=environment,
        cwd=directory,
        text=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(
                input=f"Do not use any tools. Reply with exactly this text: {marker}\n",
                timeout=180,
            )
        finally:
            # Codex may exit while a background plugin clone still writes to CODEX_HOME.
            # Stop its isolated process group before the temporary directory is removed.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    return result, events


def validate_blocked_codex(exit_code, events, stderr):
    assert exit_code != 0, "blocked Codex unexpectedly completed"
    assert not any(event["type"] == "turn.completed" for event in events), (
        "blocked turn completed"
    )
    assert any(event["type"] == "turn.failed" for event in events), (
        "no failed Codex turn"
    )
    # Codex displays error.message, not the broker's complete error envelope.
    errors = json.dumps(events) + stderr
    for required in ("403", POLICY_REASON):
        assert required in errors, f"Codex rejection missing {required}"


def validate_context(rows, scenario, model):
    calls = [
        row for row in rows if row["kind"] == "inspection" and row["case"] == scenario
    ]
    assert calls, f"{scenario}: SDK received no marked Codex context"
    for call in calls:
        assert call["harness"] == "codex" and call["model"] == model, (
            "incorrect Agent identity"
        )
        assert (
            call["host"] == "api.openai.com" and call["server_name"] == "api.openai.com"
        ), "TLS target missing"
        assert (
            call["parsing_status"] == "parsed"
            and call["protocol"] == "openai_responses"
        ), "request not parsed"
        for field in (
            "agent_has_marker",
            "json_has_marker",
            "credential_headers_absent",
            "source_process_absent",
        ):
            assert call[field] is True, f"{scenario}: context check failed: {field}"
        assert call["allow"] == (scenario == "allow"), "wrong SDK decision"
    return len(calls)


def allowed_exchange(rows):
    requests = [
        row
        for row in rows
        if row["kind"] == "event" and row["side"] == "request" and row["allow_marker"]
    ]
    return any(
        response["kind"] == "event"
        and response["side"] == "response"
        and response["allow_marker"]
        and response["response_id"]
        and response["response_id"] == request["response_id"]
        and response["session_id"] == request["session_id"]
        and response["token_usage"]["output_tokens"] > 0
        and response["agent"] == request["agent"] == "codex"
        and response["provider"] == request["provider"] == "openai"
        for request in requests
        for response in rows
    )


def run_language(language, root, model, api_key, block_only):
    directory = root / language
    directory.mkdir()
    evidence = directory / "evidence.jsonl"
    marker = f"ABYSS_SDK_{uuid.uuid4().hex}"
    allow_marker, block_marker = marker + "_ALLOW", marker + "_BLOCK"
    with contextlib.ExitStack() as cleanup:
        broker = Broker(directory, cleanup)
        environment = child_environment()
        environment.update(
            {
                "ABYSS_SDK_CODEX_ENDPOINT": broker.endpoint,
                "ABYSS_SDK_CODEX_EVIDENCE": str(evidence),
                "ABYSS_SDK_CODEX_ALLOW_MARKER": allow_marker,
                "ABYSS_SDK_CODEX_BLOCK_MARKER": block_marker,
                "PYTHONPATH": str(ROOT / "sdks/python"),
            }
        )
        log = cleanup.enter_context((directory / "sdk.log").open("w"))
        plugin = subprocess.Popen(
            plugin_command(language),
            cwd=ROOT,
            env=environment,
            stdout=log,
            stderr=subprocess.STDOUT,
        )
        cleanup.callback(stop, plugin)
        await_plugin(broker, plugin, evidence)
        # Block first: a provider/authentication failure cannot stand in for rejection.
        result, events = run_codex(
            broker, directory / "block", block_marker, model, api_key
        )
        validate_blocked_codex(result.returncode, events, result.stderr)
        blocked_calls = validate_context(records(evidence), "block", model)
        allowed_calls = 0
        if not block_only:
            result, events = run_codex(
                broker, directory / "allow", allow_marker, model, api_key
            )
            assert result.returncode == 0, (
                f"allowed Codex failed with exit {result.returncode}"
            )
            assert any(event["type"] == "turn.completed" for event in events), (
                "no real provider completion"
            )
            assert (
                directory / "allow/last-message.txt"
            ).read_text().strip() == allow_marker, "unexpected provider answer"
            allowed_calls = validate_context(records(evidence), "allow", model)
            wait_until(
                lambda: allowed_exchange(records(evidence)),
                "paired Agent events on the inspection session",
            )
        broker.shutdown()
        assert plugin.wait(timeout=10) == 0, (
            "SDK did not close cleanly after broker shutdown"
        )
        rows = records(evidence)
        assert not any(
            row["kind"] == "event" and row["block_marker"] for row in rows
        ), "blocked prompt appeared as an observed exchange"
        return {
            "sdk": language,
            "status": "passed",
            "blocked_requests": blocked_calls,
            "allowed_requests": allowed_calls,
            "live_provider_verified": not block_only,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sdk", choices=("rust", "typescript", "python"), action="append"
    )
    parser.add_argument("--model", default="gpt-5.3-codex")
    parser.add_argument(
        "--block-only",
        action="store_true",
        help="local rejection smoke test; does not verify provider access",
    )
    parser.add_argument(
        "--report", type=Path, help="write sanitized results for CI artifacts"
    )
    args = parser.parse_args()
    api_key = os.environ.get("CODEX_API_KEY", "").strip()
    if not api_key:
        parser.error(
            "CODEX_API_KEY is required (CI uses the repository Actions secret)"
        )
    summary = []
    try:
        with tempfile.TemporaryDirectory(prefix="abyss-sdk-codex-") as temporary:
            for language in args.sdk or ("rust", "typescript", "python"):
                try:
                    result = run_language(
                        language, Path(temporary), args.model, api_key, args.block_only
                    )
                except Exception as error:
                    summary.append(
                        {
                            "sdk": language,
                            "status": "failed",
                            "error": str(error),
                            "evidence": records(
                                Path(temporary) / language / "evidence.jsonl"
                            ),
                        }
                    )
                    raise
                summary.append(result)
                print(json.dumps(result), flush=True)
    finally:
        if args.report:
            args.report.parent.mkdir(parents=True, exist_ok=True)
            args.report.write_text(json.dumps(summary, indent=2) + "\n")


if __name__ == "__main__":
    main()
