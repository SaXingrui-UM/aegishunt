"""Evaluate the frozen Phase 13 core boundary from coverage.py JSON output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import yaml

RESULT_SCHEMA_VERSION = "1.0.0"


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


def _load_config(path: Path) -> tuple[str, float, tuple[str, ...], tuple[str, ...]]:
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("core coverage configuration must be a mapping")
    version = payload.get("schema_version")
    threshold = payload.get("threshold_percent")
    includes = payload.get("include")
    excludes = payload.get("exclude_from_core_only")
    if not isinstance(version, str) or not version:
        raise ValueError("core coverage schema version is required")
    if not isinstance(threshold, (int, float)) or not 0 <= threshold <= 100:
        raise ValueError("core coverage threshold must be between zero and 100")
    if not isinstance(includes, list) or not all(isinstance(item, str) for item in includes):
        raise ValueError("core coverage include rules are invalid")
    if not isinstance(excludes, list) or not all(isinstance(item, str) for item in excludes):
        raise ValueError("core coverage exclude rules are invalid")
    return version, float(threshold), tuple(includes), tuple(excludes)


def _matches(path: str, rules: tuple[str, ...]) -> bool:
    return any(path == rule or (rule.endswith("/") and path.startswith(rule)) for rule in rules)


def evaluate(
    coverage_payload: dict[str, Any],
    *,
    config_version: str,
    threshold: float,
    includes: tuple[str, ...],
    excludes: tuple[str, ...],
) -> dict[str, Any]:
    files = coverage_payload.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage JSON does not contain per-file data")
    included: list[dict[str, Any]] = []
    statements = branches = covered_statements = covered_branches = 0
    for path, data in sorted(files.items()):
        if not isinstance(path, str) or not isinstance(data, dict):
            raise ValueError("coverage JSON contains an invalid file entry")
        if not _matches(path, includes) or _matches(path, excludes):
            continue
        summary = data.get("summary")
        if not isinstance(summary, dict):
            raise ValueError(f"coverage JSON summary is missing for {path}")
        file_statements = int(summary["num_statements"])
        file_branches = int(summary["num_branches"])
        file_covered_statements = int(summary["covered_lines"])
        file_covered_branches = int(summary["covered_branches"])
        statements += file_statements
        branches += file_branches
        covered_statements += file_covered_statements
        covered_branches += file_covered_branches
        denominator = file_statements + file_branches
        included.append(
            {
                "path": path,
                "covered": file_covered_statements + file_covered_branches,
                "total": denominator,
                "percent": (
                    100.0
                    if denominator == 0
                    else 100
                    * (file_covered_statements + file_covered_branches)
                    / denominator
                ),
            }
        )
    if not included:
        raise ValueError("core coverage rules matched no files")
    denominator = statements + branches
    percent = 100 * (covered_statements + covered_branches) / denominator
    return {
        "result_schema_version": RESULT_SCHEMA_VERSION,
        "config_schema_version": config_version,
        "metric": "combined_statement_and_branch_coverage",
        "threshold_percent": threshold,
        "status": "PASS" if percent >= threshold else "FAIL",
        "core_percent": percent,
        "covered_statements": covered_statements,
        "statements": statements,
        "covered_branches": covered_branches,
        "branches": branches,
        "covered_total": covered_statements + covered_branches,
        "total": denominator,
        "file_count": len(included),
        "files": included,
    }


def write_results(output_dir: Path, result: dict[str, Any]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "core-coverage.json"
    markdown_path = output_dir / "core-coverage.md"
    json_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown = "\n".join(
        [
            "# AegisHunt Phase 13 Core Coverage Gate",
            "",
            f"- Status: **{result['status']}**",
            f"- Core combined statement/branch coverage: {result['core_percent']:.2f}%",
            f"- Required threshold: {result['threshold_percent']:.2f}%",
            f"- Covered statements: {result['covered_statements']}/{result['statements']}",
            f"- Covered branches: {result['covered_branches']}/{result['branches']}",
            f"- Included source files: {result['file_count']}",
            "",
            (
                "CLI and Streamlit are excluded only from this frozen core subset; "
                "they remain in the repository-wide branch-aware pytest gate."
            ),
            "",
        ]
    )
    markdown_path.write_text(markdown, encoding="utf-8")
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
    payload = json.loads(coverage_path.read_text(encoding="utf-8"))
    version, threshold, includes, excludes = _load_config(config_path)
    result = evaluate(
        payload,
        config_version=version,
        threshold=threshold,
        includes=includes,
        excludes=excludes,
    )
    written = write_results(output_dir, result)
    print("\n".join(path.as_posix() for path in written))
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
