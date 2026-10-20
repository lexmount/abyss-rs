"""Temporary, read-only CI diagnostics; never exports prompts or raw headers."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from pathlib import Path
from urllib.parse import urlsplit


class RetainedDiagnostics:
    """Extract counter metadata and bounded error details from retained runs."""

    @staticmethod
    def redact(value: str) -> str:
        value = re.sub(r"\x1b\[[0-9;]*m", "", value)
        value = re.sub(r"(?i)\bBearer\s+\S+", "Bearer [REDACTED]", value)
        value = re.sub(r"\b(?:sk-|sess-|ghp_|gho_)[A-Za-z0-9_-]+", "[REDACTED]", value)
        value = re.sub(
            r'(?i)(["\']?(?:authorization|api[_-]?key|access[_-]?token|refresh[_-]?token'
            r'|id[_-]?token|cookie|set-cookie)["\']?\s*[:=]\s*)'
            r'(?:"[^"]*"|\'[^\']*\'|[^\s,;}]+)',
            r"\1[REDACTED]",
            value,
        )
        value = re.sub(
            r"https?://[^\s\"<>]+",
            lambda match: urlsplit(match[0]).scheme + "://" + (urlsplit(match[0]).hostname or ""),
            value,
        )
        return value[:2000]

    @classmethod
    def error_details(cls, stdout: str, stderr: str) -> dict:
        messages = []
        for line in stdout.splitlines():
            try:
                event = json.loads(line)
            except (ValueError, TypeError):
                continue
            if not isinstance(event, dict):
                continue
            message = event.get("message") if event.get("type") == "error" else None
            if event.get("type") == "turn.failed" and isinstance(event.get("error"), dict):
                message = event["error"].get("message")
            if isinstance(message, str):
                messages.append(cls.redact(message))
        # Rust debug logs may render a JSON response body as an escaped string.
        decoded = stderr.replace('\\"', '"')
        response_errors = []
        decoder = json.JSONDecoder()
        for match in re.finditer(r"\{", decoded):
            try:
                value, _ = decoder.raw_decode(decoded[match.start():])
            except ValueError:
                continue
            if isinstance(value, dict) and isinstance(value.get("error"), dict):
                error = value["error"]
                response_errors.append({
                    key: cls.redact(error[key])
                    for key in ("message", "type", "code")
                    if isinstance(error.get(key), str)
                })
        headers = []
        header_pattern = (
            r'(?i)\b(x-ratelimit-(?:limit|remaining|reset)-[a-z-]+|retry-after'
            r'|x-request-id|request_id|cf-ray)\b["\']?\s*[:=]\s*["\']?([a-z0-9_.:-]{1,160})'
        )
        for match in re.finditer(header_pattern, decoded):
            headers.append({"name": match[1].lower(), "value": match[2]})
        return {
            "structured_error_messages": list(dict.fromkeys(messages))[-20:],
            "response_errors": response_errors[-10:],
            "limit_and_request_headers": headers[-40:],
            "http_429_mentions": len(re.findall(r"\b429\b", stderr)),
            "retry_mentions": len(re.findall(r"(?i)\bretry|\bretrying|\breconnecting", stderr)),
            "stderr_lines": len(stderr.splitlines()),
        }

    @staticmethod
    def file_info(path: Path) -> dict:
        if not path.is_file():
            return {"exists": False}
        content = path.read_bytes()
        return {"exists": True, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}

    @classmethod
    def collect(cls, root: Path) -> dict:
        result = {"exists": root.is_dir(), "phases": {}}
        coordinator = root / "coordinator"
        for phase in ("generator", "judge"):
            stdout_path = coordinator / f"{phase}.jsonl"
            stderr_path = coordinator / f"{phase}.stderr.log"
            result["phases"][phase] = {
                "stdout": cls.file_info(stdout_path),
                "stderr": cls.file_info(stderr_path),
                **cls.error_details(
                    stdout_path.read_text(errors="replace") if stdout_path.is_file() else "",
                    stderr_path.read_text(errors="replace") if stderr_path.is_file() else "",
                ),
            }
        evidence_path = coordinator / "evidence.json"
        result["evidence_file"] = cls.file_info(evidence_path)
        if evidence_path.is_file():
            evidence = json.loads(evidence_path.read_text())
            result["codex_version"] = evidence.get("run", {}).get("codex_version")
            result["section_bytes"] = {
                key: len(json.dumps(value, ensure_ascii=False).encode())
                for key, value in evidence.items()
            }
            result["executions"] = [{
                "scenario_id": execution.get("scenario_id"),
                "event_count": len(execution.get("backend_events", [])),
                "models": sorted({
                    event["llm_model"] for event in execution.get("backend_events", [])
                    if isinstance(event.get("llm_model"), str)
                }),
                "native_usage": execution.get("codex_b", {}).get("completed_usage", []),
                "exit_code": execution.get("codex_b", {}).get("exit_code"),
                "duration_seconds": execution.get("codex_b", {}).get("duration_seconds"),
                "accounting_matches": execution.get("usage_accounting", {}).get("matches"),
            } for execution in evidence.get("executions", [])]
        return result


def main() -> None:
    run_ids = os.environ["DIAGNOSTIC_RUN_IDS"].split()
    if not 1 <= len(run_ids) <= 12 or any(not re.fullmatch(r"\d+-\d+", value) for value in run_ids):
        raise ValueError("Expected 1-12 run-attempt IDs")
    runtime = Path(os.environ["RUNNER_TEMP"])
    login = subprocess.run(["codex", "login", "status"], capture_output=True, text=True, timeout=30)
    status = (login.stdout + login.stderr).lower()
    auth = "chatgpt" if "chatgpt" in status else "api_key" if "api key" in status else "unknown"
    result = {
        "auth_mode_now": auth,
        "auth_status_exit_code": login.returncode,
        "model_environment": {
            name: os.environ.get(name)
            for name in (
                "ABYSS_AGENT_E2E_GENERATOR_MODEL",
                "ABYSS_AGENT_E2E_B_MODEL",
                "ABYSS_AGENT_E2E_JUDGE_MODEL",
            )
        },
        "credential_environment_present": {
            name: bool(os.environ.get(name))
            for name in ("CODEX_API_KEY", "OPENAI_API_KEY")
        },
        "runs": {
            run_id: RetainedDiagnostics.collect(runtime / f"abyss-agent-e2e-{run_id}")
            for run_id in run_ids
        },
    }
    output = json.dumps(result, ensure_ascii=False, indent=2)
    (runtime / "codex-retained-diagnostics.json").write_text(output + "\n")
    print(output)


if __name__ == "__main__":
    main()
