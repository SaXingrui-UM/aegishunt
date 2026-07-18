"""Regression tests for current Phase 6 status truthfulness."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_reports_phase_six_review_state_without_starting_phase_seven() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Phase 5 is fully closed on `main`" in content
    assert "Phase 6 anomaly-engine implementation is complete" in content
    assert "awaits PR review" in content
    assert "Phase 7 has not started" in content
    assert "pipeline verification only" in content
    assert "missed\nall labeled anomalies" in content
    assert "normalized anomaly score is not probability" in content


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


def test_progress_and_release_record_phase_six_without_phase_seven_scope() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-06.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 6 implementation checkpoint",
    )
    release_current = _section(
        release,
        "## Objective and status",
        "## Completed scope",
    )
    normalized_progress_current = " ".join(progress_current.split())
    normalized_release_current = " ".join(release_current.split())

    for content in (progress, release):
        assert "phase/06-anomaly-detection" in content
        assert "Implementation complete — awaiting PR review" in content
        assert "Phase 7" in content and "Not started" in content
        assert "pipeline verification only" in content.lower()
        assert "phase-06-complete" in content

    assert "Current phase | Phase 6" in normalized_progress_current
    assert "Status | Implementation complete — awaiting PR review" in normalized_progress_current
    assert "Phase 7 status | Not started" in normalized_progress_current
    assert "Phase complete" not in progress_current

    assert "Implementation complete — awaiting PR review" in normalized_release_current
    assert "Phase 7 has not started" in normalized_release_current
    assert "PR, merge commit, and completion Tag are `pending`" in normalized_release_current

    assert "iforest-64-full" in release
    assert "Isolation Forest missed all controlled validation/test anomalies" in release
    assert "not a public benchmark" in release
