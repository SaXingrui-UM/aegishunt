from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from scripts.run_phase13_robustness import load_matrix, write_results


def test_phase13_robustness_matrix_is_versioned_bounded_and_complete() -> None:
    version, seed, scenarios = load_matrix(
        Path("configs/hardening/phase-13-robustness.yaml")
    )

    assert version == "1.0.0"
    assert seed == 20260729
    assert len(scenarios) == 17
    assert len({scenario.identifier for scenario in scenarios}) == len(scenarios)
    assert all(scenario.test_nodes for scenario in scenarios)
    assert all(
        not Path(node).is_absolute()
        for scenario in scenarios
        for node in scenario.test_nodes
    )


def test_load_matrix_rejects_duplicate_scenario_ids(tmp_path: Path) -> None:
    matrix = tmp_path / "matrix.yaml"
    matrix.write_text(
        """
schema_version: "1"
random_seed: 1
scenarios:
  - id: ROB-001
    test_nodes: [tests/a.py]
  - id: ROB-001
    test_nodes: [tests/b.py]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate robustness scenario"):
        load_matrix(matrix)


def test_robustness_results_are_machine_and_human_reviewable(tmp_path: Path) -> None:
    row = {
        "identifier": "ROB-001",
        "category": "input",
        "requirement": "reject malformed input",
        "expected": "fails closed",
        "test_nodes": ["tests/test_input.py::test_reject"],
        "status": "PASS",
        "exit_code": 0,
        "duration_seconds": 0.1,
        "evidence": "1 passed",
    }
    payload = {
        "result_schema_version": "1.0.0",
        "matrix_schema_version": "1.0.0",
        "random_seed": 1,
        "summary": {"total": 1, "passed": 1, "failed": 0},
        "results": [row],
    }

    json_path, csv_path, markdown_path = write_results(tmp_path, payload)

    assert json.loads(json_path.read_text(encoding="utf-8"))["summary"]["passed"] == 1
    with csv_path.open(encoding="utf-8", newline="") as source:
        assert list(csv.DictReader(source))[0]["status"] == "PASS"
    report = markdown_path.read_text(encoding="utf-8")
    assert "controlled offline robustness checks" in report
    assert "not a public benchmark" in report
