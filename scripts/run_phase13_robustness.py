"""Execute the versioned Phase 13 robustness matrix in isolated pytest processes."""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROBUSTNESS_RESULT_SCHEMA_VERSION = "1.0.0"


@dataclass(frozen=True, slots=True)
class Scenario:
    identifier: str
    category: str
    requirement: str
    expected: str
    test_nodes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ScenarioResult:
    identifier: str
    category: str
    requirement: str
    expected: str
    test_nodes: tuple[str, ...]
    status: str
    exit_code: int
    duration_seconds: float
    evidence: str


def load_matrix(path: Path) -> tuple[str, int, tuple[Scenario, ...]]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("robustness matrix must be a mapping")
    version = document.get("schema_version")
    seed = document.get("random_seed")
    raw_scenarios = document.get("scenarios")
    if not isinstance(version, str) or not version:
        raise ValueError("robustness matrix schema_version is required")
    if not isinstance(seed, int):
        raise ValueError("robustness matrix random_seed must be an integer")
    if not isinstance(raw_scenarios, list) or not raw_scenarios:
        raise ValueError("robustness matrix scenarios cannot be empty")

    scenarios: list[Scenario] = []
    seen: set[str] = set()
    for raw in raw_scenarios:
        if not isinstance(raw, dict):
            raise ValueError("robustness scenario must be a mapping")
        identifier = raw.get("id")
        nodes = raw.get("test_nodes")
        if not isinstance(identifier, str) or not identifier:
            raise ValueError("robustness scenario id is required")
        if identifier in seen:
            raise ValueError(f"duplicate robustness scenario id: {identifier}")
        if not isinstance(nodes, list) or not nodes or not all(
            isinstance(node, str) and node and not Path(node).is_absolute()
            for node in nodes
        ):
            raise ValueError(f"{identifier} test_nodes must be non-empty relative node ids")
        seen.add(identifier)
        scenarios.append(
            Scenario(
                identifier=identifier,
                category=str(raw.get("category", "")),
                requirement=str(raw.get("requirement", "")),
                expected=str(raw.get("expected", "")),
                test_nodes=tuple(nodes),
            )
        )
    return version, seed, tuple(scenarios)


def _compact_evidence(output: str, project_root: Path) -> str:
    normalized = output.replace(str(project_root), "<PROJECT_ROOT>").strip()
    lines = [line for line in normalized.splitlines() if line.strip()]
    return " | ".join(lines[-6:])[-2_000:]


def run_scenario(
    scenario: Scenario,
    *,
    project_root: Path,
    seed: int,
) -> ScenarioResult:
    environment = os.environ.copy()
    environment.update(
        {
            "PYTHONPATH": "src",
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONHASHSEED": str(seed),
        }
    )
    command = [
        sys.executable,
        "-m",
        "pytest",
        "--no-cov",
        "-q",
        *scenario.test_nodes,
    ]
    started = time.perf_counter()
    completed = subprocess.run(
        command,
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=600,
        check=False,
    )
    duration = time.perf_counter() - started
    evidence = _compact_evidence(completed.stdout + completed.stderr, project_root)
    return ScenarioResult(
        identifier=scenario.identifier,
        category=scenario.category,
        requirement=scenario.requirement,
        expected=scenario.expected,
        test_nodes=scenario.test_nodes,
        status="PASS" if completed.returncode == 0 else "FAIL",
        exit_code=completed.returncode,
        duration_seconds=duration,
        evidence=evidence,
    )


def _markdown(payload: dict[str, Any]) -> str:
    totals = payload["summary"]
    lines = [
        "# AegisHunt Phase 13 Robustness Experiment Results",
        "",
        (
            "These are controlled offline robustness checks on a development host. "
            "They are not a public benchmark or production reliability claim."
        ),
        "",
        f"- Matrix schema: `{payload['matrix_schema_version']}`",
        f"- Result schema: `{payload['result_schema_version']}`",
        f"- Random seed: `{payload['random_seed']}`",
        f"- Total: {totals['total']}",
        f"- Passed: {totals['passed']}",
        f"- Failed: {totals['failed']}",
        "- Network: not required",
        "- Privilege: no root or administrator access",
        "",
        "| ID | Category | Expected invariant | Status | Duration s |",
        "|---|---|---|---:|---:|",
    ]
    for result in payload["results"]:
        lines.append(
            f"| {result['identifier']} | {result['category']} | "
            f"{result['expected']} | {result['status']} | "
            f"{result['duration_seconds']:.3f} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- PASS means the named regression test passed in an isolated pytest process.",
            "- FAIL is never converted to skip or xfail by this runner.",
            "- Full command evidence remains in the JSON and CSV results.",
            "- The matrix does not rerun frozen model-selection or test-set evidence.",
            "",
        ]
    )
    return "\n".join(lines)


def write_results(output_dir: Path, payload: dict[str, Any]) -> tuple[Path, ...]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "robustness-results.json"
    csv_path = output_dir / "robustness-results.csv"
    markdown_path = output_dir / "robustness-results.md"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    rows = payload["results"]
    with csv_path.open("w", encoding="utf-8", newline="") as destination:
        fieldnames = list(rows[0])
        writer = csv.DictWriter(
            destination,
            fieldnames=fieldnames,
            lineterminator="\n",
        )
        writer.writeheader()
        writer.writerows(
            {
                **row,
                "test_nodes": ";".join(row["test_nodes"]),
            }
            for row in rows
        )
    markdown_path.write_text(_markdown(payload), encoding="utf-8")
    return json_path, csv_path, markdown_path


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--matrix",
        type=Path,
        default=Path("configs/hardening/phase-13-robustness.yaml"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("reports/hardening/phase-13/robustness"),
    )
    parser.add_argument("--smoke", action="store_true")
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    project_root = Path(__file__).resolve().parents[1]
    matrix_path = (
        arguments.matrix
        if arguments.matrix.is_absolute()
        else project_root / arguments.matrix
    )
    output_dir = (
        arguments.output_dir
        if arguments.output_dir.is_absolute()
        else project_root / arguments.output_dir
    )
    matrix_version, seed, scenarios = load_matrix(matrix_path)
    selected = scenarios[:1] if arguments.smoke else scenarios
    results = tuple(
        run_scenario(scenario, project_root=project_root, seed=seed)
        for scenario in selected
    )
    payload: dict[str, Any] = {
        "result_schema_version": ROBUSTNESS_RESULT_SCHEMA_VERSION,
        "matrix_schema_version": matrix_version,
        "recorded_at": datetime.now(UTC).isoformat(),
        "random_seed": seed,
        "execution": {
            "offline": True,
            "root_required": False,
            "live_capture": False,
            "isolated_pytest_process_per_scenario": True,
        },
        "summary": {
            "total": len(results),
            "passed": sum(result.status == "PASS" for result in results),
            "failed": sum(result.status == "FAIL" for result in results),
        },
        "results": [asdict(result) for result in results],
    }
    written = write_results(output_dir, payload)
    print("\n".join(path.as_posix() for path in written))
    return 0 if all(result.status == "PASS" for result in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
