from __future__ import annotations

import json
from pathlib import Path

from scripts.check_phase13_core_coverage import evaluate, write_results


def test_core_coverage_uses_combined_statement_and_branch_counts(tmp_path: Path) -> None:
    result = evaluate(
        {
            "files": {
                "src/aegishunt/api/app.py": {
                    "summary": {
                        "num_statements": 10,
                        "covered_lines": 8,
                        "num_branches": 4,
                        "covered_branches": 3,
                    }
                },
                "src/aegishunt/frontend/app.py": {
                    "summary": {
                        "num_statements": 100,
                        "covered_lines": 0,
                        "num_branches": 100,
                        "covered_branches": 0,
                    }
                },
            }
        },
        config_version="1.0.0",
        threshold=75.0,
        includes=("src/aegishunt/api/", "src/aegishunt/frontend/"),
        excludes=("src/aegishunt/frontend/",),
    )

    assert result["core_percent"] == 100 * 11 / 14
    assert result["status"] == "PASS"
    assert result["file_count"] == 1
    json_path, markdown_path = write_results(tmp_path, result)
    assert json.loads(json_path.read_text(encoding="utf-8"))["status"] == "PASS"
    assert "78.57%" in markdown_path.read_text(encoding="utf-8")


def test_core_coverage_gate_fails_below_frozen_threshold() -> None:
    result = evaluate(
        {
            "files": {
                "src/aegishunt/config.py": {
                    "summary": {
                        "num_statements": 10,
                        "covered_lines": 6,
                        "num_branches": 10,
                        "covered_branches": 4,
                    }
                }
            }
        },
        config_version="1.0.0",
        threshold=80.0,
        includes=("src/aegishunt/config.py",),
        excludes=(),
    )

    assert result["core_percent"] == 50.0
    assert result["status"] == "FAIL"
