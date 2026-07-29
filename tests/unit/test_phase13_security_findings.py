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
