from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.check_phase13_core_coverage import (
    EXPECTED_CORE_PACKAGES,
    evaluate,
    write_results,
)


def _packages() -> dict[str, tuple[str, ...]]:
    return {
        name: (f"src/aegishunt/{name}/",)
        if name not in {"artifact_io", "config"}
        else (f"src/aegishunt/{name}.py",)
        for name in EXPECTED_CORE_PACKAGES
    }


def _summary(*, covered: int = 9, total: int = 10) -> dict[str, int]:
    return {
        "num_statements": total,
        "covered_lines": covered,
        "num_branches": total,
        "covered_branches": covered,
    }


def _payload(*, package_covered: dict[str, int] | None = None) -> dict[str, object]:
    overrides = package_covered or {}
    files: dict[str, object] = {}
    for name, rules in _packages().items():
        rule = rules[0]
        path = rule if rule.endswith(".py") else f"{rule}module.py"
        files[path] = {"summary": _summary(covered=overrides.get(name, 9))}
    files["src/aegishunt/frontend/app.py"] = {"summary": _summary()}
    statements = sum(item["summary"]["num_statements"] for item in files.values())
    covered = sum(item["summary"]["covered_lines"] for item in files.values())
    branches = sum(item["summary"]["num_branches"] for item in files.values())
    covered_branches = sum(item["summary"]["covered_branches"] for item in files.values())
    return {
        "files": files,
        "totals": {
            "num_statements": statements,
            "covered_lines": covered,
            "num_branches": branches,
            "covered_branches": covered_branches,
        },
    }


def _evaluate(payload: dict[str, object]) -> dict[str, object]:
    return evaluate(
        payload,
        config_version="2.0.0",
        repository_threshold=85.0,
        package_threshold=80.0,
        packages=_packages(),
    )


def test_coverage_gate_evaluates_repository_and_each_package(tmp_path: Path) -> None:
    result = _evaluate(_payload())

    assert result["status"] == "PASS"
    assert result["repository"]["percent"] == 90.0
    assert [item["name"] for item in result["packages"]] == list(EXPECTED_CORE_PACKAGES)
    assert all(item["percent"] == 90.0 for item in result["packages"])
    json_path, markdown_path = write_results(tmp_path, result)
    assert json.loads(json_path.read_text(encoding="utf-8"))["status"] == "PASS"
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "| artifact_io | 1 | 9/10 | 9/10 | 90.00% | 80.00% | PASS |" in markdown
    assert "Repository branch-aware combined coverage: 90.00%" in markdown


def test_coverage_gate_fails_when_one_package_is_below_eighty() -> None:
    result = _evaluate(_payload(package_covered={"flows": 7}))

    flows = next(item for item in result["packages"] if item["name"] == "flows")
    assert flows["percent"] == 70.0
    assert flows["status"] == "FAIL"
    assert result["status"] == "FAIL"


def test_coverage_gate_fails_when_repository_is_below_eighty_five() -> None:
    payload = _payload()
    payload["totals"] = _summary(covered=8, total=10)

    result = _evaluate(payload)

    assert result["repository"]["percent"] == 80.0
    assert result["repository"]["status"] == "FAIL"
    assert result["status"] == "FAIL"


def test_coverage_gate_rejects_missing_package_definition() -> None:
    packages = _packages()
    packages.pop("flows")

    with pytest.raises(ValueError, match="boundary is incomplete"):
        evaluate(
            _payload(),
            config_version="2.0.0",
            repository_threshold=85.0,
            package_threshold=80.0,
            packages=packages,
        )


def test_coverage_gate_rejects_package_with_zero_matching_files() -> None:
    payload = _payload()
    payload["files"].pop("src/aegishunt/flows/module.py")

    with pytest.raises(ValueError, match="flows matched no files"):
        _evaluate(payload)


def test_coverage_gate_rejects_malformed_coverage_json() -> None:
    payload = _payload()
    payload["files"]["src/aegishunt/api/module.py"]["summary"].pop("num_branches")

    with pytest.raises(ValueError, match="summary is incomplete"):
        _evaluate(payload)
