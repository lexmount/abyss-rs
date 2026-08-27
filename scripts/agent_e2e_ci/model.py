"""Validated contracts shared by the scenario generator and semantic judge."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import PurePosixPath
from typing import Any


MAX_SCENARIOS = 3
MAX_FILES_PER_SCENARIO = 8
MAX_FILE_BYTES = 16 * 1024
MAX_TOTAL_FILE_BYTES = 32 * 1024
MAX_PROMPT_BYTES = 12 * 1024
SCENARIO_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
HEX_COLOR_PATTERN = re.compile(r"^#[0-9a-fA-F]{6}$")
ALLOWED_IMAGE_PATTERNS = frozenset(
    {"checkerboard", "horizontal_stripes", "vertical_stripes", "quadrants"}
)
ORDERED_COVERAGE_TARGETS = (
    "tool_call",
    "tool_result",
    "image_input",
    "session_turn",
    "token_usage",
)
ALLOWED_COVERAGE_TARGETS = frozenset(ORDERED_COVERAGE_TARGETS)


class ContractError(ValueError):
    """Raised when Codex emits data outside the CI contract."""


class VerdictStatus(Enum):
    """Semantic outcomes accepted from the independent Codex judge."""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class ScenarioFile:
    """One bounded UTF-8 fixture created inside a disposable workspace."""

    path: str
    content: str

    @classmethod
    def from_value(cls, value: Any) -> "ScenarioFile":
        item = _object(value, "scenario file")
        _exact_keys(item, {"path", "content"}, "scenario file")
        path = _safe_relative_path(_string(item["path"], "scenario file path"))
        content = _string(item["content"], f"content for {path}")
        if len(content.encode("utf-8")) > MAX_FILE_BYTES:
            raise ContractError(f"scenario file {path!r} exceeds {MAX_FILE_BYTES} bytes")
        return cls(path=path, content=content)


@dataclass(frozen=True)
class ImageSpec:
    """A bounded raster fixture description materialized by trusted code."""

    width: int
    height: int
    pattern: str
    palette: tuple[str, ...]

    @classmethod
    def from_value(cls, value: Any) -> "ImageSpec":
        item = _object(value, "image spec")
        _exact_keys(item, {"width", "height", "pattern", "palette"}, "image spec")
        width = _integer(item["width"], "image width")
        height = _integer(item["height"], "image height")
        if not 32 <= width <= 256 or not 32 <= height <= 256:
            raise ContractError("image dimensions must each be between 32 and 256 pixels")
        pattern = _string(item["pattern"], "image pattern")
        if pattern not in ALLOWED_IMAGE_PATTERNS:
            raise ContractError(f"unsupported image pattern: {pattern}")
        palette_value = item["palette"]
        if not isinstance(palette_value, list) or not 2 <= len(palette_value) <= 4:
            raise ContractError("image palette must contain between two and four colors")
        palette = tuple(_string(color, "image palette color") for color in palette_value)
        if any(not HEX_COLOR_PATTERN.fullmatch(color) for color in palette):
            raise ContractError("image palette colors must use #RRGGBB syntax")
        return cls(width=width, height=height, pattern=pattern, palette=palette)


@dataclass(frozen=True)
class Scenario:
    """A Codex-generated black-box task and its disposable fixtures."""

    scenario_id: str
    title: str
    objective: str
    prompt: str
    files: tuple[ScenarioFile, ...]
    image: ImageSpec
    coverage_targets: tuple[str, ...]
    rationale: str

    @classmethod
    def from_value(cls, value: Any) -> "Scenario":
        item = _object(value, "scenario")
        expected_keys = {
            "id",
            "title",
            "objective",
            "prompt",
            "files",
            "image",
            "coverage_targets",
            "rationale",
        }
        _exact_keys(item, expected_keys, "scenario")
        scenario_id = _string(item["id"], "scenario id")
        if not SCENARIO_ID_PATTERN.fullmatch(scenario_id):
            raise ContractError(
                "scenario id must contain only lowercase letters, digits, underscores, and hyphens"
            )
        title = _bounded_string(item["title"], "scenario title", 160)
        objective = _bounded_string(item["objective"], "scenario objective", 1_000)
        prompt = _bounded_string(item["prompt"], "scenario prompt", MAX_PROMPT_BYTES)
        rationale = _bounded_string(item["rationale"], "scenario rationale", 2_000)

        files_value = item["files"]
        if not isinstance(files_value, list) or not 1 <= len(files_value) <= MAX_FILES_PER_SCENARIO:
            raise ContractError(
                f"scenario files must contain between one and {MAX_FILES_PER_SCENARIO} entries"
            )
        files = tuple(ScenarioFile.from_value(entry) for entry in files_value)
        paths = [entry.path for entry in files]
        if len(paths) != len(set(paths)):
            raise ContractError("scenario fixture paths must be unique")
        path_parts = [tuple(path.split("/")) for path in paths]
        for index, candidate in enumerate(path_parts):
            for other_index, other in enumerate(path_parts):
                is_prefix = len(candidate) < len(other) and other[: len(candidate)] == candidate
                if index != other_index and is_prefix:
                    raise ContractError(
                        "scenario fixture paths must not contain file/directory conflicts"
                    )
        if sum(len(entry.content.encode("utf-8")) for entry in files) > MAX_TOTAL_FILE_BYTES:
            raise ContractError(
                f"scenario fixtures exceed the {MAX_TOTAL_FILE_BYTES}-byte aggregate limit"
            )

        targets_value = item["coverage_targets"]
        targets_object = _object(targets_value, "coverage_targets")
        _exact_keys(
            targets_object,
            set(ALLOWED_COVERAGE_TARGETS),
            "coverage_targets",
        )
        for target in ORDERED_COVERAGE_TARGETS:
            if not isinstance(targets_object[target], bool):
                raise ContractError(f"coverage target {target} must be a boolean")
        targets = tuple(
            target for target in ORDERED_COVERAGE_TARGETS if targets_object[target]
        )
        required = {"tool_call", "tool_result", "image_input"}
        if not required.issubset(targets):
            raise ContractError(
                "every scenario must target tool_call, tool_result, and image_input coverage"
            )

        return cls(
            scenario_id=scenario_id,
            title=title,
            objective=objective,
            prompt=prompt,
            files=files,
            image=ImageSpec.from_value(item["image"]),
            coverage_targets=targets,
            rationale=rationale,
        )


@dataclass(frozen=True)
class ScenarioPlan:
    """The complete randomized data set emitted by Codex A."""

    run_id: str
    seed: int
    scenarios: tuple[Scenario, ...]

    @classmethod
    def from_value(
        cls,
        value: Any,
        *,
        expected_run_id: str,
        expected_seed: int,
        max_scenarios: int = MAX_SCENARIOS,
    ) -> "ScenarioPlan":
        item = _object(value, "scenario plan")
        _exact_keys(item, {"run_id", "seed", "scenarios"}, "scenario plan")
        run_id = _string(item["run_id"], "run id")
        seed = _integer(item["seed"], "seed")
        if run_id != expected_run_id:
            raise ContractError("scenario plan run_id does not match the current CI run")
        if seed != expected_seed:
            raise ContractError("scenario plan seed does not match the current CI seed")
        scenarios_value = item["scenarios"]
        if not isinstance(scenarios_value, list) or not 1 <= len(scenarios_value) <= max_scenarios:
            raise ContractError(
                f"scenario plan must contain between one and {max_scenarios} scenarios"
            )
        scenarios = tuple(Scenario.from_value(entry) for entry in scenarios_value)
        scenario_ids = [scenario.scenario_id for scenario in scenarios]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ContractError("scenario ids must be unique")
        return cls(run_id=run_id, seed=seed, scenarios=scenarios)


@dataclass(frozen=True)
class Verdict:
    """A validated high-level outcome from Codex A's independent judge phase."""

    status: VerdictStatus
    run_id: str
    seed: int
    summary: str
    raw: dict[str, Any]

    @classmethod
    def from_value(
        cls,
        value: Any,
        *,
        expected_run_id: str,
        expected_seed: int,
        scenario_ids: set[str],
    ) -> "Verdict":
        item = _object(value, "verdict")
        required_keys = {
            "status",
            "run_id",
            "seed",
            "coverage",
            "scenario_results",
            "issues",
            "summary",
            "recommended_action",
        }
        _exact_keys(item, required_keys, "verdict")
        try:
            status = VerdictStatus(_string(item["status"], "verdict status"))
        except ValueError as error:
            raise ContractError("verdict status must be pass, fail, or inconclusive") from error
        run_id = _string(item["run_id"], "verdict run id")
        seed = _integer(item["seed"], "verdict seed")
        if run_id != expected_run_id or seed != expected_seed:
            raise ContractError("verdict identity does not match the current CI run")
        summary = _bounded_string(item["summary"], "verdict summary", 4_000)
        _bounded_string(item["recommended_action"], "recommended action", 4_000)
        coverage = _object(item["coverage"], "verdict coverage")
        coverage_keys = {
            "tool_call_observed",
            "matching_tool_result_observed",
            "image_transmitted",
            "session_turn_coherent",
            "token_usage_consistent",
            "run_isolated",
            "notes",
        }
        _exact_keys(coverage, coverage_keys, "verdict coverage")
        for key in coverage_keys - {"notes"}:
            if not isinstance(coverage[key], bool):
                raise ContractError(f"verdict coverage {key} must be a boolean")
        _bounded_string(coverage["notes"], "verdict coverage notes", 4_000)
        _string_array(item["issues"], "verdict issues", 2_000)
        scenario_results = item["scenario_results"]
        if not isinstance(scenario_results, list) or len(scenario_results) != len(scenario_ids):
            raise ContractError("verdict must contain exactly one result per scenario")
        returned_ids: set[str] = set()
        for result in scenario_results:
            result_object = _object(result, "scenario verdict")
            _exact_keys(
                result_object,
                {"id", "outcome", "observed_behavior", "comparisons", "issues"},
                "scenario verdict",
            )
            scenario_id = _string(result_object["id"], "scenario verdict id")
            if scenario_id in returned_ids:
                raise ContractError("verdict contains duplicate scenario results")
            returned_ids.add(scenario_id)
            outcome = _string(result_object["outcome"], "scenario verdict outcome")
            if outcome not in {"match", "mismatch", "inconclusive"}:
                raise ContractError("scenario verdict outcome is invalid")
            _bounded_string(
                result_object["observed_behavior"],
                "scenario observed_behavior",
                6_000,
            )
            comparisons = result_object["comparisons"]
            if not isinstance(comparisons, list) or not comparisons:
                raise ContractError("scenario verdict must include at least one comparison")
            for comparison in comparisons:
                comparison_object = _object(comparison, "scenario comparison")
                _exact_keys(
                    comparison_object,
                    {"criterion", "actual", "backend", "outcome", "explanation"},
                    "scenario comparison",
                )
                _bounded_string(comparison_object["criterion"], "comparison criterion", 500)
                for key in ("actual", "backend", "explanation"):
                    limit = 6_000 if key in {"actual", "backend"} else 4_000
                    _bounded_string(comparison_object[key], f"comparison {key}", limit)
                comparison_outcome = _string(
                    comparison_object["outcome"], "comparison outcome"
                )
                if comparison_outcome not in {"match", "mismatch", "not_observed"}:
                    raise ContractError("comparison outcome is invalid")
            _string_array(result_object["issues"], "scenario verdict issues", 2_000)
        if returned_ids != scenario_ids:
            raise ContractError("verdict scenario ids do not match the generated plan")
        if status is VerdictStatus.PASS:
            coverage_complete = all(coverage[key] is True for key in coverage_keys - {"notes"})
            outcomes_match = all(
                result["outcome"] == "match" for result in scenario_results
            )
            if not coverage_complete or not outcomes_match:
                raise ContractError(
                    "a passing verdict requires complete coverage and matching scenario outcomes"
                )
        return cls(status=status, run_id=run_id, seed=seed, summary=summary, raw=item)


def _safe_relative_path(value: str) -> str:
    if "\\" in value:
        raise ContractError("scenario file paths must use forward slashes")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ContractError("scenario file path must not traverse directories")
    if any(part == ".git" for part in raw_parts):
        raise ContractError("scenario file path must not target Git metadata")
    if any(any(ord(character) < 32 for character in part) for part in raw_parts):
        raise ContractError("scenario file path must not contain control characters")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts:
        raise ContractError("scenario file path must be relative")
    if path.name == "input.png":
        raise ContractError("scenario file path is reserved by the CI harness")
    if len(value.encode("utf-8")) > 240:
        raise ContractError("scenario file path is too long")
    return path.as_posix()


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractError(f"{label} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ContractError(f"{label} keys do not match contract; missing={missing}, extra={extra}")


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ContractError(f"{label} must be a non-empty string")
    return value


def _bounded_string(value: Any, label: str, byte_limit: int) -> str:
    result = _string(value, label)
    if len(result.encode("utf-8")) > byte_limit:
        raise ContractError(f"{label} exceeds {byte_limit} bytes")
    return result


def _integer(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ContractError(f"{label} must be an integer")
    return value


def _string_array(value: Any, label: str, item_byte_limit: int) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ContractError(f"{label} must be an array")
    result: list[str] = []
    for item in value:
        result.append(_bounded_string(item, f"{label} entry", item_byte_limit))
    return tuple(result)
