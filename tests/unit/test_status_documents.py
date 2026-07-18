"""Regression tests for current Phase 5 status truthfulness."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


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

    for content in (progress, release):
        assert "a8d2a3ad324b89e3d8b8d703d00e73e82a2e6574" in content
        assert "phase/06-anomaly-detection" in content
        assert "Phase 6" in content and "Not started" in content
    assert "Final status closure awaiting PR merge" in progress
    assert "Final status closure awaiting PR merge" in release
    assert "PM-DEF-001 was corrected by PR #14" in release
    assert "metadata PR #15 awaits user review" not in progress
    assert "open and ready for\n  user review" not in release
