"""Evaluate repository and per-package Phase 13 branch-aware coverage gates."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import yaml

RESULT_SCHEMA_VERSION = "2.0.0"
EXPECTED_CORE_PACKAGES = (
    "api",
    "artifact_io",
    "cases",
    "config",
    "correlation",
    "datasets",
    "demo",
    "detection",
    "explainability",
    "feedback",
    "flows",
    "hunting",
    "ingestion",
    "ml",
    "runtime",
    "schemas",
    "storage",
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage-json", type=Path, default=Path("coverage.json"))
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("configs/hardening/phase-13-core-coverage.yaml"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/hardening/phase-13/coverage"),
    )
    return parser.parse_args()


def _rules(value: object, *, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ValueError(f"{label} rules are invalid")
    return tuple(value)


def _threshold(value: object, *, label: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 100:
        raise ValueError(f"{label} must be between zero and 100")
    return float(value)


def load_config(path: Path) -> tuple[str, float, float, dict[str, tuple[str, ...]]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("core coverage configuration must be a mapping")
    version = payload.get("schema_version")
    if not isinstance(version, str) or not version:
        raise ValueError("core coverage schema version is required")
    repository_threshold = _threshold(
        payload.get("repository_threshold_percent"),
        label="repository coverage threshold",
    )
    package_threshold = _threshold(
        payload.get("package_threshold_percent"),
        label="package coverage threshold",
    )
    raw_packages = payload.get("packages")
    if not isinstance(raw_packages, dict):
        raise ValueError("core coverage packages must be a mapping")
    if tuple(sorted(raw_packages)) != EXPECTED_CORE_PACKAGES:
        raise ValueError("core coverage package boundary is incomplete or unexpected")
    packages: dict[str, tuple[str, ...]] = {}
    for name in EXPECTED_CORE_PACKAGES:
        raw = raw_packages[name]
        if not isinstance(raw, dict):
            raise ValueError(f"core coverage package {name} must be a mapping")
        packages[name] = _rules(raw.get("include"), label=f"package {name} include")
    return version, repository_threshold, package_threshold, packages


def _matches(path: str, rules: tuple[str, ...]) -> bool:
    return any(path == rule or (rule.endswith("/") and path.startswith(rule)) for rule in rules)


def _counts(summary: Mapping[str, Any], *, label: str) -> tuple[int, int, int, int]:
    required = ("num_statements", "covered_lines", "num_branches", "covered_branches")
    if any(key not in summary for key in required):
        raise ValueError(f"coverage JSON summary is incomplete for {label}")
    try:
        statements = int(summary["num_statements"])
        covered_statements = int(summary["covered_lines"])
        branches = int(summary["num_branches"])
        covered_branches = int(summary["covered_branches"])
    except (TypeError, ValueError) as error:
        raise ValueError(f"coverage JSON summary is invalid for {label}") from error
    if (
        min(statements, covered_statements, branches, covered_branches) < 0
        or covered_statements > statements
        or covered_branches > branches
    ):
        raise ValueError(f"coverage JSON counts are invalid for {label}")
    return statements, covered_statements, branches, covered_branches


def _coverage_result(
    *,
    name: str,
    threshold: float,
    files: list[tuple[str, Mapping[str, Any]]],
) -> dict[str, Any]:
    if not files:
        raise ValueError(f"coverage package {name} matched no files")
    statements = covered_statements = branches = covered_branches = 0
    for path, summary in files:
        item = _counts(summary, label=path)
        statements += item[0]
        covered_statements += item[1]
        branches += item[2]
        covered_branches += item[3]
    total = statements + branches
    if total == 0:
        raise ValueError(f"coverage package {name} has no measurable statements or branches")
    covered = covered_statements + covered_branches
    percent = 100.0 * covered / total
    return {
        "name": name,
        "status": "PASS" if percent >= threshold else "FAIL",
        "threshold_percent": threshold,
        "percent": percent,
        "source_file_count": len(files),
        "statements": statements,
        "covered_statements": covered_statements,
        "branches": branches,
        "covered_branches": covered_branches,
        "total": total,
        "covered_total": covered,
        "files": [path for path, _summary in files],
    }


def evaluate(
    coverage_payload: dict[str, Any],
    *,
    config_version: str,
    repository_threshold: float,
    package_threshold: float,
    packages: Mapping[str, tuple[str, ...]],
) -> dict[str, Any]:
    """Evaluate the repository total and every frozen core package independently."""

    files = coverage_payload.get("files")
    totals = coverage_payload.get("totals")
    if not isinstance(files, dict) or not isinstance(totals, dict):
        raise ValueError("coverage JSON does not contain per-file data and repository totals")
    if tuple(sorted(packages)) != EXPECTED_CORE_PACKAGES:
        raise ValueError("core coverage package boundary is incomplete or unexpected")

    normalized: dict[str, Mapping[str, Any]] = {}
    for path, data in sorted(files.items()):
        if not isinstance(path, str) or not isinstance(data, dict):
            raise ValueError("coverage JSON contains an invalid file entry")
        summary = data.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"coverage JSON summary is missing for {path}")
        normalized[path] = summary

    package_results: list[dict[str, Any]] = []
    matched_paths: dict[str, str] = {}
    for name in EXPECTED_CORE_PACKAGES:
        package_files = [
            (path, summary)
            for path, summary in normalized.items()
            if _matches(path, packages[name])
        ]
        for path, _summary in package_files:
            if path in matched_paths:
                raise ValueError(
                    f"coverage file {path} overlaps packages {matched_paths[path]} and {name}"
                )
            matched_paths[path] = name
        package_results.append(
            _coverage_result(
                name=name,
                threshold=package_threshold,
                files=package_files,
            )
        )

    repository_counts = _counts(totals, label="repository totals")
    repository = _coverage_result(
        name="repository",
        threshold=repository_threshold,
        files=[("<repository totals>", dict(zip(
            ("num_statements", "covered_lines", "num_branches", "covered_branches"),
            repository_counts,
            strict=True,
        )))],
    )
    repository["source_file_count"] = len(normalized)
    repository["files"] = []
    status = (
        "PASS"
        if repository["status"] == "PASS"
        and all(item["status"] == "PASS" for item in package_results)
        else "FAIL"
    )
    return {
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "config_schema_version": config_version,
        "metric": "combined_statement_and_branch_coverage",
        "status": status,
        "repository": repository,
        "packages": package_results,
    }


def write_results(output_dir: Path, result: dict[str, Any]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "core-coverage.json"
    markdown_path = output_dir / "core-coverage.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    repository = result["repository"]
    lines = [
        "# AegisHunt Phase 13 Coverage Gates",
        "",
        f"- Overall status: **{result['status']}**",
        (
            "- Repository branch-aware combined coverage: "
            f"{repository['percent']:.2f}% (threshold {repository['threshold_percent']:.2f}%)"
        ),
        "",
        "| Core package | Files | Statements | Branches | Combined | Threshold | Status |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for package in result["packages"]:
        lines.append(
            f"| {package['name']} | {package['source_file_count']} | "
            f"{package['covered_statements']}/{package['statements']} | "
            f"{package['covered_branches']}/{package['branches']} | "
            f"{package['percent']:.2f}% | {package['threshold_percent']:.2f}% | "
            f"{package['status']} |"
        )
    lines.extend(
        [
            "",
            (
                "Top-level CLI and Streamlit frontend are repository-only coverage surfaces. "
                "They remain included in the 85% repository gate and are not omitted from pytest."
            ),
            "",
        ]
    )
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    return json_path, markdown_path


def main() -> int:
    arguments = _arguments()
    project_root = Path(__file__).resolve().parents[1]
    coverage_path = (
        arguments.coverage_json
        if arguments.coverage_json.is_absolute()
        else project_root / arguments.coverage_json
    )
    config_path = (
        arguments.config
        if arguments.config.is_absolute()
        else project_root / arguments.config
    )
    output_dir = (
        arguments.output_dir
        if arguments.output_dir.is_absolute()
        else project_root / arguments.output_dir
    )
    try:
        payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"coverage JSON cannot be loaded: {error}") from error
    if not isinstance(payload, dict):
        raise ValueError("coverage JSON root must be a mapping")
    version, repository_threshold, package_threshold, packages = load_config(config_path)
    result = evaluate(
        payload,
        config_version=version,
        repository_threshold=repository_threshold,
        package_threshold=package_threshold,
        packages=packages,
    )
    written = write_results(output_dir, result)
    print("\n".join(path.as_posix() for path in written))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
