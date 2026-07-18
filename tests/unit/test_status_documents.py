"""Regression tests for current Phase 5 status truthfulness."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_reports_closed_phase_five_without_starting_phase_six() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")

    assert "Phase 5 is complete on `main`" in content
    assert "PR #14" in content
    assert "PR #15" in content
    assert "Phase 6 has not started" in content
    assert "awaits\nreview" not in content
    assert "pipeline verification only" in content


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


def test_progress_and_release_record_merged_metadata_and_planned_phase_six() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-05.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 5 implementation checkpoint",
    )
    release_current = _section(
        release,
        "## Objective and status",
        "## Original completed scope",
    )
    normalized_progress_current = " ".join(progress_current.split())
    normalized_release_current = " ".join(release_current.split())

    for content in (progress, release):
        assert "a8d2a3ad324b89e3d8b8d703d00e73e82a2e6574" in content
        assert "cc3b1ac52d93d786ab5552c4f9be4b08b3408696" in content
        assert "phase/06-anomaly-detection" in content
        assert "Phase 6" in content and "Not started" in content
        assert "phase-05-complete" in content
        assert "phase-05-pm-def-001-complete" in content

    assert "Phase complete — corrected and fully closed" in normalized_progress_current
    assert "Final status PR | [#16]" in normalized_progress_current
    assert "merged into `main` as `cc3b1ac" in normalized_progress_current
    assert "PM-DEF-001 | Resolved" in normalized_progress_current
    assert "Phase 6 status | Not started" in normalized_progress_current
    assert "Final status closure awaiting PR merge" not in progress_current

    assert "Phase complete — corrected and fully closed" in normalized_release_current
    assert "PM-DEF-001 is **Resolved**" in normalized_release_current
    assert "final status PR #16 are merged" in normalized_release_current
    assert "Phase 6 has not started" in normalized_release_current
    assert "Final status closure awaiting PR merge" not in release_current

    assert "0.19178394648427863" in release
    assert "pipeline fixture, not a public benchmark" in release
