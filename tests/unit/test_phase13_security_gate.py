from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts.run_phase13_security import (
    SecretCandidate,
    evaluate_bandit,
    evaluate_pip_audit,
    evaluate_secret_candidates,
    generated_pr_body_candidates,
    run_dependency_scan,
    tracked_secret_candidates,
)


def test_pip_audit_parser_accepts_clean_complete_result() -> None:
    result = evaluate_pip_audit(
        {"dependencies": [{"name": "fastapi", "version": "1.0", "vulns": []}]}
    )

    assert result == {
        "status": "PASS",
        "dependency_count": 1,
        "finding_count": 0,
        "findings": [],
    }


def test_pip_audit_parser_blocks_vulnerable_dependency() -> None:
    result = evaluate_pip_audit(
        {
            "dependencies": [
                {
                    "name": "runtime-package",
                    "version": "1.0",
                    "vulns": [
                        {
                            "id": "CVE-2099-0001",
                            "fix_versions": ["1.1"],
                            "severity": "HIGH",
                        }
                    ],
                }
            ]
        }
    )

    assert result["status"] == "FAIL"
    assert result["finding_count"] == 1
    assert result["findings"][0]["severity"] == "HIGH"


def test_pip_audit_parser_rejects_missing_results() -> None:
    with pytest.raises(ValueError, match="does not contain dependencies"):
        evaluate_pip_audit({"error": "network unavailable"})


def test_dependency_tool_failure_is_not_reported_as_pass(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_run(
        command: list[str],
        *,
        cwd: Path,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        del cwd, check
        return subprocess.CompletedProcess(command, returncode=2, stdout="", stderr="offline")

    monkeypatch.setattr("scripts.run_phase13_security._run", fake_run)

    with pytest.raises(RuntimeError, match="did not produce JSON"):
        run_dependency_scan(tmp_path, tmp_path)


def test_bandit_parser_blocks_medium_and_rejects_suppression_hiding() -> None:
    result = evaluate_bandit(
        {
            "results": [
                {"issue_severity": "LOW"},
                {"issue_severity": "MEDIUM"},
            ],
            "errors": [],
            "metrics": {"_totals": {"nosec": 1}},
        }
    )

    assert result["status"] == "FAIL"
    assert result["blocking_findings"] == 1
    assert result["suppressions"] == 1


def test_secret_gate_requires_exact_candidate_and_never_emits_raw_value() -> None:
    reviewed = SecretCandidate(
        path="tests/example.py",
        detector_type="Secret Keyword",
        secret_hash="a" * 40,
    )
    unexpected = SecretCandidate(
        path="src/example.py",
        detector_type="Secret Keyword",
        secret_hash="a" * 40,
    )
    result = evaluate_secret_candidates(
        tracked=(unexpected,),
        history=(),
        allowlist={
            reviewed: {
                "rationale": "test fixture",
                "reviewed_as": "false_positive",
            }
        },
    )

    serialized = json.dumps(result, sort_keys=True)
    assert result["status"] == "FAIL"
    assert result["confirmed_secrets"] == 1
    assert "actual-secret-value" not in serialized
    assert "src/example.py" in serialized


def test_detect_secrets_scans_real_tracked_file_without_raw_value(
    tmp_path: Path,
) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    fixture = tmp_path / "credential.py"
    fixture.write_text('password = "deliberately-invalid-fixture"\\n', encoding="utf-8")
    subprocess.run(["git", "add", "credential.py"], cwd=tmp_path, check=True)

    candidates = tracked_secret_candidates(tmp_path)

    assert len(candidates) == 1
    assert candidates[0].path == "credential.py"
    assert candidates[0].detector_type == "Secret Keyword"
    assert not hasattr(candidates[0], "secret_value")


def test_github_pull_request_body_is_scanned_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    event = tmp_path / "event.json"
    event.write_text(
        json.dumps(
            {
                "pull_request": {
                    "body": 'password = "deliberately-invalid-pr-fixture"'
                }
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_EVENT_PATH", str(event))

    candidates, scanned = generated_pr_body_candidates(tmp_path)

    assert scanned is True
    assert len(candidates) == 1
    assert candidates[0].path == ".github/generated/phase-13-pr.md"
    assert candidates[0].detector_type == "Secret Keyword"
    assert not hasattr(candidates[0], "secret_value")
