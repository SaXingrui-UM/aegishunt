"""Regression tests for current Phase 9 pull-request status truthfulness."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_records_phase_nine_without_starting_phase_ten() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    current = _section(content, "## Current status", "## Planned architecture")
    normalized = " ".join(current.split())

    assert "Phases 0–8 are complete" in current
    assert "phase/09-hypothesis-engine" in current
    assert "PR [#25]" in current
    assert "PR [#26]" in normalized
    assert "f622faec6513a9fadcba11b73d2fbe1239779217" in current
    assert "d7b3f3c5dd0c2e22f6e8721875f5ba738ea58edc" in current
    assert "phase-08-complete" in current
    assert "complete and awaiting pull-request review" in normalized
    assert "Phase 10 is **Not started**" in normalized
    assert "pipeline verification only" in current
    assert "recommendation is **inconclusive**" in normalized
    assert "was not shown to be superior" in normalized
    assert "family-macro LOAO Recall was lower than anomaly-only" in normalized
    assert "missed held-out exfiltration and reconnaissance" in normalized
    assert "negative results are retained" in normalized.lower()
    assert "operational suspiciousness risk" in normalized
    assert "not attack probability" in normalized
    assert "alert is a prompt for analyst review" in normalized
    assert "not attack probabilities" in normalized
    assert "hypotheses are not facts" in normalized
    assert "never executed" in normalized
    assert "public benchmark" in current and "production validation" in current
    assert "proof of zero-day detection" in current
    assert "pending merge" not in current
    assert "Phase 10 implementation" not in normalized


def test_pm_def_001_is_resolved_without_erasing_history() -> None:
    defects = (PROJECT_ROOT / "docs/known_defects.md").read_text(encoding="utf-8")
    pm_def_001 = defects.split("## DEF-004", maxsplit=1)[0]

    assert "- Status: Resolved" in pm_def_001
    assert "0.19178394648427863" in pm_def_001
    assert "isotonic" in pm_def_001 and "Brier `0.0`" in pm_def_001
    assert "76f79972dff778f5d30d550bc6da78583e338fa1" in pm_def_001
    assert "phase-05-complete" in pm_def_001
    assert "phase-05-pm-def-001-complete" in pm_def_001
    assert "[#15]" in pm_def_001
    assert "pull/15" in pm_def_001
    assert "not public\n  benchmark or real-world performance evidence" in pm_def_001


def test_progress_and_release_record_phase_nine_without_phase_ten_scope() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-09.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 9 implementation checkpoint",
    )
    release_current = _section(
        release,
        "## Objective and status",
        "## Completed scope",
    )
    normalized_progress_current = " ".join(progress_current.split())
    normalized_release_current = " ".join(release_current.split())

    for content in (progress, release):
        assert "phase/09-hypothesis-engine" in content
        assert "Phase 10" in content and "not started" in content.lower()
        assert "not attack" in content.lower()
        assert "confirmed" in content.lower()

    assert "Current phase | Phase 9" in normalized_progress_current
    assert "Status | Implementation complete — awaiting PR review" in normalized_progress_current
    assert (
        "Phase 9 status | Implementation complete — awaiting PR review"
        in normalized_progress_current
    )
    assert "Phase 10 status | Not started" in normalized_progress_current
    assert "phase/09-hypothesis-engine" in progress_current
    assert "Current branch | `phase/09-hypothesis-engine`" in normalized_progress_current

    assert "Status: **Implementation complete — awaiting PR review**" in release_current
    assert "Pull request: [#28]" in normalized_release_current
    assert "open and ready for review" in normalized_release_current
    assert "CI pending" in normalized_release_current
    assert "Completion tag: pending" in normalized_release_current
    assert "Phase 10: Not started" in normalized_release_current

    assert "ADR 0018" in release
    assert "event-time" in release
    assert "ATT&CK" in release
    assert "not_executed" in release
    assert "automatic confirmation" in release
