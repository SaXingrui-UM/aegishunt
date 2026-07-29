"""Contract tests for the complete Phase 13 security findings ledger."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from scripts.validate_phase13_security_findings import (
    ALLOWED_DISPOSITIONS,
    BASELINE_REVISION,
    SecurityFindingsLedgerError,
    load_and_validate,
    validate_ledger,
)

LEDGER_PATH = Path("configs/hardening/phase-13-security-findings.json")
SECURITY_FINDINGS_PATH = Path("docs/security_findings.md")
SECURITY_BASELINE_PATH = Path("docs/phase-13-security-baseline.md")
SECRET_HISTORY_EVIDENCE_PATHS = (
    Path("docs/security_review.md"),
    SECURITY_BASELINE_PATH,
    Path("docs/releases/phase-13.md"),
    Path("docs/codex_progress.md"),
)


def _payload() -> dict[str, object]:
    return json.loads(LEDGER_PATH.read_text(encoding="utf-8"))


def test_canonical_ledger_represents_all_baseline_findings() -> None:
    payload = _payload()
    counts = validate_ledger(payload)

    assert payload["baseline_revision"] == BASELINE_REVISION
    findings = payload["findings"]
    assert isinstance(findings, list)
    assert len(findings) == 80
    assert sum(finding["severity"] == "medium" for finding in findings) == 7
    assert sum(finding["severity"] == "low" for finding in findings) == 73
    assert set(counts).issubset(ALLOWED_DISPOSITIONS)
    assert "Untriaged" not in counts


def test_canonical_ledger_fixed_findings_bind_commit_and_regression() -> None:
    findings = _payload()["findings"]
    assert isinstance(findings, list)

    fixed = [finding for finding in findings if finding["disposition"] == "Fixed"]
    assert len(fixed) == 9
    assert all(finding["fix_commit"] for finding in fixed)
    assert all("::test_" in finding["regression_test"] for finding in fixed)


def test_canonical_ledger_accepted_risks_have_individual_rationales() -> None:
    findings = _payload()["findings"]
    assert isinstance(findings, list)

    accepted = [finding for finding in findings if finding["disposition"] == "Accepted risk"]
    assert accepted
    for finding in accepted:
        assert finding["required_attacker_capability"]
        assert finding["current_mitigation"]
        assert finding["residual_impact"]
        assert finding["phase_14_action"]


def test_ledger_rejects_missing_or_duplicate_finding_number() -> None:
    payload = copy.deepcopy(_payload())
    findings = payload["findings"]
    assert isinstance(findings, list)
    findings[1]["original_finding_number"] = 1

    with pytest.raises(SecurityFindingsLedgerError, match="ordered 1..80"):
        validate_ledger(payload)


def test_ledger_rejects_unapproved_disposition() -> None:
    payload = copy.deepcopy(_payload())
    findings = payload["findings"]
    assert isinstance(findings, list)
    findings[7]["disposition"] = "Untriaged"

    with pytest.raises(SecurityFindingsLedgerError, match="unsupported disposition"):
        validate_ledger(payload)


def test_ledger_rejects_fixed_finding_without_test_evidence() -> None:
    payload = copy.deepcopy(_payload())
    findings = payload["findings"]
    assert isinstance(findings, list)
    findings[0]["regression_test"] = None

    with pytest.raises(SecurityFindingsLedgerError, match="regression test"):
        validate_ledger(payload)


def test_ledger_loader_fails_closed_for_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "findings.json"
    path.write_text("{", encoding="utf-8")

    with pytest.raises(SecurityFindingsLedgerError, match="unable to read"):
        load_and_validate(path)


def test_security_documents_record_the_explicit_final_rescan_waiver() -> None:
    findings = SECURITY_FINDINGS_PATH.read_text(encoding="utf-8")
    baseline = SECURITY_BASELINE_PATH.read_text(encoding="utf-8")
    combined = f"{findings}\n{baseline}"
    normalized_findings = " ".join(findings.split())
    normalized_baseline = " ".join(baseline.split())

    assert "explicitly waived by the user" in findings
    assert "No final rescan result is claimed" in normalized_findings
    assert (
        "not represented as a formal rescan or substitute result"
        in normalized_findings
    )
    assert "was not executed" in baseline
    assert "No final rescan result is claimed" in normalized_baseline
    assert (
        "not represented as a formal rescan or substitute result"
        in normalized_baseline
    )
    assert "separate merge gate" not in combined
    assert "still requires a formal Codex Security" not in combined


def test_security_documents_preserve_dependency_and_bounded_history_truth() -> None:
    baseline = SECURITY_BASELINE_PATH.read_text(encoding="utf-8")
    review = Path("docs/security_review.md").read_text(encoding="utf-8")

    assert "114 installed distributions under CPython 3.12.13" in baseline
    assert "110 installed distributions in a clean CPython 3.11" in baseline
    assert "113 installed distributions" not in baseline
    assert "`pip check` reports no broken requirements" in baseline
    assert "Unique historical text blobs scanned: 1,264" in review
    assert "Binary blobs safely skipped: 18" in review
    assert "Oversized blobs safely skipped: 1" in review
    assert "Stale allowlist entries: 0" in review
    assert "Unreviewed candidates: 0" in review
    assert "Confirmed secrets: 0" in review

    for path in SECRET_HISTORY_EVIDENCE_PATHS:
        evidence = path.read_text(encoding="utf-8")
        normalized = " ".join(evidence.split())
        assert "1,264" in normalized
        assert (
            "18 binary" in normalized
            or "Binary blobs safely skipped: 18" in normalized
        )
        assert (
            "one oversized" in normalized
            or "Oversized blobs safely skipped: 1" in normalized
        )
        assert (
            "zero confirmed secrets" in normalized
            or "0 confirmed secrets" in normalized
        )
        assert (
            "zero unreviewed candidates" in normalized
            or "0 unreviewed candidates" in normalized
            or "Unreviewed candidates: 0" in normalized
        )
        assert (
            "zero stale allowlist" in normalized
            or "0 stale allowlist" in normalized
            or "Stale allowlist entries: 0" in normalized
        )
        assert "bounded oversized" in normalized
        assert "does not mean every reachable blob was scanned" in normalized
        assert "complete reachable Git blob history" not in normalized
        assert "complete-history" not in normalized
        assert "full-history" not in normalized
