#!/usr/bin/env python3
"""Verify HTTPS proxy authentication through real broker startup, REST and sockets."""

import base64
import copy
import http.client
import json
import ssl
import sys
import tempfile
from pathlib import Path

from blackbox_abyss_broker_upstream import (
    Broker,
    LocalServer,
    NextHop,
    Origin,
    explicit_request,
    network,
    openssl,
    read_all,
)


def proxy_tls(broker, hostname):
    key = broker.directory / f"{hostname}.key"
    csr = broker.directory / f"{hostname}.csr"
    cert = broker.directory / f"{hostname}.pem"
    extension = broker.directory / f"{hostname}.ext"
    extension.write_text(
        f"subjectAltName=DNS:{hostname}\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        f"/CN={hostname}",
        "-keyout",
        key,
        "-out",
        csr,
    )
    # Deliberately share the test issuer with the target to detect trust leakage.
    openssl(
        "x509",
        "-req",
        "-in",
        csr,
        "-CA",
        broker.ca_file,
        "-CAkey",
        broker.ca_key,
        "-CAcreateserial",
        "-days",
        "1",
        "-extfile",
        extension,
        "-out",
        cert,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    context.set_alpn_protocols(["http/1.1"])
    return context


def rejected_update(broker, payload):
    previous = broker.request("GET", "/v1/network/config")
    api = http.client.HTTPConnection(broker.api, timeout=5)
    try:
        api.request(
            "PUT",
            "/v1/network/config",
            json.dumps(payload),
            {
                "Authorization": f"Bearer {broker.token}",
                "Content-Type": "application/json",
            },
        )
        response = api.getresponse()
        body = response.read()
        assert response.status == 400, (response.status, body)
        assert b"password-sentinel" not in body
    finally:
        api.close()
    assert broker.request("GET", "/v1/network/config") == previous


def request_target(broker, tls=False):
    if broker.flow_socket:
        from blackbox_abyss_broker_transparent_upstream import framed_connection

        raw = framed_connection(
            broker, "tls.invalid" if tls else "plain.invalid", 443 if tls else 80
        )
    else:
        raw = broker.connect("tls.invalid:443" if tls else "plain.invalid:80")
    with raw:
        if tls:
            context = ssl.create_default_context(cafile=str(broker.ca_file))
            with context.wrap_socket(raw, server_hostname="tls.invalid") as stream:
                stream.sendall(
                    b"GET /probe HTTP/1.1\r\nHost: tls.invalid\r\nConnection: close\r\n\r\n"
                )
                return read_all(stream)
        raw.sendall(
            b"GET /probe HTTP/1.1\r\nHost: plain.invalid\r\nConnection: close\r\n\r\n"
        )
        return read_all(raw)


def run_checks(broker, proxy):
    credentials = broker.directory / "proxy-credentials.json"
    valid = {"username": "user-USERNAME", "password": "password-sentinel:extra"}
    credentials.write_text(json.dumps(valid))
    credentials.chmod(0o600)
    proxy.proxy_authorization = b"Basic " + base64.b64encode(
        f"{valid['username']}:{valid['password']}".encode()
    )
    configured = network(proxy)
    configured["upstream"].update(
        {
            "credentials_file": str(credentials),
            "handshake_timeout_ms": 1000,
        }
    )
    # Basic authentication also works over the existing HTTP transport.
    broker.request("PUT", "/v1/network/config", configured)
    assert request_target(broker).endswith(b"secure")
    proxy.tls = proxy_tls(broker, "localhost")
    configured["upstream"]["endpoint"] = f"https://localhost:{proxy.server_address[1]}"
    configured["upstream"]["ca_file"] = str(broker.ca_file)
    assert broker.request("PUT", "/v1/network/config", configured) == configured
    assert request_target(broker).endswith(b"secure")
    assert request_target(broker, tls=True).endswith(b"secure"), (
        "nested target TLS failed"
    )
    if not broker.flow_socket:
        explicit_request(broker)
    assert all(
        b"Proxy-Authorization" not in request for request in proxy.origin.requests
    )
    assert all(
        b"Proxy-Authorization" not in request for request in proxy.tls_origin.requests
    )
    assert all(b"agent-secret" not in request for request in proxy.requests)

    # The route retains credential material until an explicit configuration application.
    credentials.write_text(
        json.dumps({"username": "user-USERNAME", "password": "wrong"})
    )
    assert request_target(broker).endswith(b"secure")
    broker.request("PUT", "/v1/network/config", configured)
    before = proxy.origin.accepted
    if broker.flow_socket:
        assert b"secure" not in request_target(broker)
    else:
        with broker.connect(f"127.0.0.1:{proxy.origin.server_address[1]}", 502):
            pass
    assert proxy.origin.accepted == before, "authentication failure fell back to direct"
    rows = broker.observations(lambda row: row.get("proxy_status") == 407)
    assert rows[0]["technical_error_code"] == "upstream_proxy_auth_required"
    assert rows[0]["http_status"] is None
    credentials.write_text(json.dumps(valid))
    broker.request("PUT", "/v1/network/config", configured)

    # Material errors reject the update without changing the current route.
    missing = copy.deepcopy(configured)
    missing["upstream"]["credentials_file"] = str(broker.directory / "missing.json")
    rejected_update(broker, missing)
    invalid_ca = broker.directory / "invalid-ca.pem"
    invalid_ca.write_text("password-sentinel malformed certificate")
    invalid = copy.deepcopy(configured)
    invalid["upstream"]["ca_file"] = str(invalid_ca)
    rejected_update(broker, invalid)
    assert request_target(broker).endswith(b"secure")

    # A trusted issuer does not permit a different server identity; no CONNECT or
    # proxy credential bytes may be sent before successful TLS verification.
    for wrong_name in (False, True):
        candidate = copy.deepcopy(configured)
        if wrong_name:
            proxy.tls = proxy_tls(broker, "wrong.invalid")
        else:
            candidate["upstream"].pop("ca_file")
        broker.request("PUT", "/v1/network/config", candidate)
        before = (len(proxy.requests), proxy.origin.accepted)
        if broker.flow_socket:
            assert b"secure" not in request_target(broker)
        else:
            with broker.connect(f"127.0.0.1:{proxy.origin.server_address[1]}", 502):
                pass
        assert (len(proxy.requests), proxy.origin.accepted) == before
        rows = broker.observations(
            lambda row: row.get("technical_error_code") == "upstream_proxy_tls_error"
        )
        assert rows[0]["hop"] == "abyss_to_upstream_proxy"
        assert rows[0]["stage"] == "tls_handshake"
        assert rows[0]["failure_class"] == "tls_error"
        assert rows[0]["proxy_status"] is None and rows[0]["http_status"] is None
    proxy.tls = proxy_tls(broker, "localhost")
    broker.request("PUT", "/v1/network/config", configured)

    broker.request(
        "PUT",
        "/v1/mitm/config",
        {
            "tls_decryption": {"default_action": "intercept", "rules": []},
        },
    )
    try:
        assert b"secure" not in request_target(broker, tls=True), (
            "proxy CA leaked into target trust"
        )
    except (OSError, EOFError):
        pass
    broker.observations(
        lambda row: row.get("technical_error_code") == "provider_tls_error"
    )
    broker.request(
        "PUT",
        "/v1/mitm/config",
        {
            "tls_decryption": {"default_action": "passthrough", "rules": []},
        },
    )
    broker.restart()
    assert broker.request("GET", "/v1/network/config") == configured
    assert request_target(broker, tls=True).endswith(b"secure")

    # Also load HTTPS + authentication directly from startup TOML.
    config_path = broker.directory / "broker-config.toml"
    startup = config_path.read_text().split("[proxy.upstream]")[0]
    config_path.write_text(
        startup
        + "[proxy.upstream]\n"
        + "\n".join(
            f"{key} = {json.dumps(value)}"
            for key, value in configured["upstream"].items()
        )
        + "\n"
    )
    (broker.home / "runtime-policy.toml").write_text(
        'schema_version = 1\n[mitm.tls_decryption]\ndefault_action = "passthrough"\n'
        "[hooks.harness_usage]\nenabled = false\n"
    )
    broker.restart()
    assert request_target(broker, tls=True).endswith(b"secure")
    serialized = json.dumps(broker.request("GET", "/v1/network/config"))
    serialized += json.dumps(broker.request("GET", "/v1/support/diagnostics"))
    serialized += json.dumps(
        broker.request("GET", "/v1/network/observations?limit=100")
    )
    serialized += (broker.home / "runtime-policy.toml").read_text()
    serialized += (broker.directory / "broker.log").read_text()
    assert "password-sentinel" not in serialized
    assert proxy.proxy_authorization.decode() not in serialized


def main():
    for transparent in [False, True] if sys.platform == "darwin" else [False]:
        origin, tls_origin, proxy = (
            LocalServer(Origin),
            LocalServer(Origin),
            LocalServer(NextHop),
        )
        proxy.origin, proxy.tls_origin = origin, tls_origin
        broker = None
        try:
            with tempfile.TemporaryDirectory(
                prefix="abyss-https-upstream-"
            ) as temporary:
                broker = Broker(Path(temporary), proxy, transparent=transparent)
                try:
                    run_checks(broker, proxy)
                finally:
                    broker.close()
            print(
                f"PASS: HTTPS proxy + Basic auth, certificate rejection, trust isolation, hot update, restart, secret isolation; transparent={transparent}"
            )
        finally:
            proxy.close()
            tls_origin.close()
            origin.close()


if __name__ == "__main__":
    main()
