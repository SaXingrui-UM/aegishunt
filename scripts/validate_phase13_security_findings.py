"""Validate the complete, reviewable Phase 13 Codex Security findings ledger."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

BASELINE_REVISION = "75c73bc86a40a78a22edde5fb175359a7b755c05"
EXPECTED_TOTAL = 80
EXPECTED_SEVERITY_COUNTS = {"medium": 7, "low": 73}
ALLOWED_DISPOSITIONS = frozenset(
    {
        "Fixed",
        "Duplicate",
        "False positive",
        "Not reachable",
        "Accepted risk",
        "Deferred to Phase 14",
        "Needs further validation",
    }
)
REQUIRED_FINDING_FIELDS = frozenset(
    {
        "original_finding_number",
        "tracking_id",
        "title",
        "severity",
        "confidence",
        "affected_subsystem",
        "root_cause_cluster",
        "reachability",
        "required_attacker_capability",
        "disposition",
        "fix_commit",
        "regression_test",
        "current_mitigation",
        "residual_impact",
        "phase_14_action",
        "notes",
    }
)


class SecurityFindingsLedgerError(ValueError):
    """Raised when the Phase 13 security ledger violates its contract."""


def _require_text(finding: dict[str, Any], field: str, number: int) -> str:
    value = finding[field]
    if not isinstance(value, str) or not value.strip():
        raise SecurityFindingsLedgerError(
            f"finding {number} field {field!r} must be non-empty text"
        )
    return value.strip()


def validate_ledger(payload: object) -> dict[str, int]:
    """Validate ledger structure, completeness, dispositions, and fixed evidence."""

    if not isinstance(payload, dict):
        raise SecurityFindingsLedgerError("ledger root must be an object")
    if payload.get("schema_version") != "1.0.0":
        raise SecurityFindingsLedgerError("ledger schema_version must be 1.0.0")
    if payload.get("baseline_revision") != BASELINE_REVISION:
        raise SecurityFindingsLedgerError("ledger baseline revision is incorrect")
    if payload.get("baseline_finding_count") != EXPECTED_TOTAL:
        raise SecurityFindingsLedgerError("ledger baseline count is incorrect")
    findings = payload.get("findings")
    if not isinstance(findings, list) or len(findings) != EXPECTED_TOTAL:
        raise SecurityFindingsLedgerError("ledger must contain exactly 80 findings")

    expected_numbers = list(range(1, EXPECTED_TOTAL + 1))
    actual_numbers: list[int] = []
    tracking_ids: set[str] = set()
    severity_counts: Counter[str] = Counter()
    disposition_counts: Counter[str] = Counter()

    for finding in findings:
        if not isinstance(finding, dict):
            raise SecurityFindingsLedgerError("every finding must be an object")
        missing = REQUIRED_FINDING_FIELDS - set(finding)
        if missing:
            raise SecurityFindingsLedgerError(
                f"finding is missing fields: {', '.join(sorted(missing))}"
            )
        number = finding["original_finding_number"]
        if not isinstance(number, int):
            raise SecurityFindingsLedgerError("finding number must be an integer")
        actual_numbers.append(number)
        tracking_id = _require_text(finding, "tracking_id", number)
        if tracking_id in tracking_ids:
            raise SecurityFindingsLedgerError(f"duplicate tracking ID: {tracking_id}")
        tracking_ids.add(tracking_id)

        severity = _require_text(finding, "severity", number).lower()
        severity_counts[severity] += 1
        disposition = _require_text(finding, "disposition", number)
        if disposition not in ALLOWED_DISPOSITIONS:
            raise SecurityFindingsLedgerError(
                f"finding {number} has unsupported disposition {disposition!r}"
            )
        disposition_counts[disposition] += 1

        for field in (
            "title",
            "confidence",
            "affected_subsystem",
            "root_cause_cluster",
            "reachability",
            "required_attacker_capability",
            "current_mitigation",
            "residual_impact",
            "phase_14_action",
            "notes",
        ):
            _require_text(finding, field, number)

        fix_commit = finding["fix_commit"]
        regression_test = finding["regression_test"]
        if disposition == "Fixed":
            if not isinstance(fix_commit, str) or len(fix_commit.strip()) < 7:
                raise SecurityFindingsLedgerError(
                    f"fixed finding {number} must name its fix commit"
                )
            if not isinstance(regression_test, str) or "::test_" not in regression_test:
                raise SecurityFindingsLedgerError(
                    f"fixed finding {number} must name its regression test"
                )
        elif fix_commit is not None or regression_test is not None:
            raise SecurityFindingsLedgerError(
                f"non-fixed finding {number} cannot claim fix evidence"
            )

        if disposition == "Accepted risk":
            for field in (
                "required_attacker_capability",
                "current_mitigation",
                "residual_impact",
                "phase_14_action",
            ):
                _require_text(finding, field, number)

    if actual_numbers != expected_numbers:
        raise SecurityFindingsLedgerError(
            "finding numbers must be unique, complete, and deterministically ordered 1..80"
        )
    if dict(severity_counts) != EXPECTED_SEVERITY_COUNTS:
        raise SecurityFindingsLedgerError(
            f"severity inventory differs from baseline: {dict(severity_counts)}"
        )
    return dict(sorted(disposition_counts.items()))


def load_and_validate(path: Path) -> dict[str, int]:
    """Load and validate one ledger file."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SecurityFindingsLedgerError("unable to read security ledger") from exc
    return validate_ledger(payload)


def main() -> int:
    """Validate the canonical ledger and print a sanitized disposition summary."""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ledger",
        type=Path,
        default=Path("configs/hardening/phase-13-security-findings.json"),
    )
    args = parser.parse_args()
    counts = load_and_validate(args.ledger)
    print(
        json.dumps(
            {
                "status": "PASS",
                "baseline_revision": BASELINE_REVISION,
                "finding_count": EXPECTED_TOTAL,
                "dispositions": counts,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
