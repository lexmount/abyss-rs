#!/usr/bin/env python3
"""Exercise the installed CLI entry point against an isolated real broker and worker."""

import argparse
import json
import os
from contextlib import contextmanager
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from threading import Thread
from time import monotonic, sleep


class CatalogHandler(SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass


@contextmanager
def running_broker(binaries, root, env):
    runtime = root / "runtime"
    startup = runtime / "startup-info.json"
    startup.unlink(missing_ok=True)
    with subprocess.Popen(
        [binaries / "abyss-broker", "--config", root / "broker.toml",
         "--auth-token-file", runtime / "broker.token", "--startup-info-file", startup],
        env=env, stdout=subprocess.DEVNULL,
    ) as broker:
        try:
            deadline = monotonic() + 10
            while not startup.exists():
                if broker.poll() is not None or monotonic() > deadline:
                    raise RuntimeError("broker did not publish its startup identity")
                sleep(0.05)
            yield
        finally:
            broker.terminate()
            broker.wait(timeout=10)


def verify(binaries, root):
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    ca = root / "ca"
    ca.mkdir(mode=0o700)
    pem = ca / "abyss-root-ca.pem"
    for args in [
        ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
         "-subj", "/CN=Model route CLI fixture", "-addext", "basicConstraints=critical,CA:TRUE",
         "-keyout", ca / "abyss-root-ca-key.pem", "-out", pem],
        ["x509", "-in", pem, "-outform", "DER", "-out", ca / "abyss-root-ca.der"],
    ]:
        subprocess.run(["openssl", *args], check=True, capture_output=True)
    (root / "broker.toml").write_text(
        'schema_version = 1\n[proxy]\nmode = "explicit"\nlisten_addr = "127.0.0.1:0"\n'
        f'[ca]\npath = {json.dumps(str(ca))}\n'
    )
    env = {**os.environ, "ABYSS_HOME": str(root)}
    fixtures = root / "fixtures"
    fixtures.mkdir()
    path = fixtures / "catalog.json"
    path.write_text(json.dumps({
        "harness_providers": {"codex": ["test"]},
        "providers": {"test": {"base_url": "https://provider.example/v1", "models": ["a"],
                               "credentials": {"team": {"kind": "api_key", "api_key": "fixture-private"}}}},
    }))

    def cli(*args):
        result = subprocess.run(
            [binaries / "abyss", "model-route", *args], env=env, check=True,
            capture_output=True, timeout=15,
        )
        assert b"fixture-private" not in result.stdout + result.stderr
        return json.loads(result.stdout)

    with running_broker(binaries, root, env):
        assert cli("import-file", path)["source"] == str(path)
        assert cli("models", "test", "team") == [{"id": "a"}]
        with ThreadingHTTPServer(("127.0.0.1", 0), partial(CatalogHandler, directory=fixtures)) as server:
            Thread(target=server.serve_forever, daemon=True).start()
            url = f"http://127.0.0.1:{server.server_port}/catalog.json"
            try:
                assert cli("import-url", url)["source"] == url
            finally:
                server.shutdown()
        selected = cli("select", "codex", "test", "team", "a")["selections"]
        assert selected == {"codex": {"provider": "test", "credential": "team", "model": "a"}}
        assert cli("state")["selections"] == selected
    with running_broker(binaries, root, env):
        assert cli("state")["selections"] == selected
        assert cli("disable", "codex")["selections"] == {}
        assert cli("clear")["catalog"]["providers"] == {}
    print("PASS: real CLI and broker, file and HTTP import, model listing, selection, restart, disable, clear, secret redaction")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    with TemporaryDirectory(prefix="abyss-model-cli-") as directory:
        verify(parser.parse_args().bin_dir.resolve(), Path(directory).resolve())
