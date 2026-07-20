"""Regression tests for current Phase 7 status truthfulness."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_records_phase_seven_without_starting_phase_eight() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    normalized = " ".join(content.split())

    assert "Phases 0–6 are closed" in content
    assert "Phase 7 dual-engine fusion implementation is complete" in normalized
    assert "Phase 8" in content and "not implemented" in content
    assert "pipeline verification only" in content
    assert "recommendation is **inconclusive**" in normalized
    assert "lower family-macro LOAO recall" in content
    assert "Fusion score is not probability, risk, severity, or attack confirmation" in normalized


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


def test_progress_and_release_record_phase_seven_without_phase_eight_scope() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-07.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 7 implementation checkpoint",
    )
    release_current = _section(
        release,
        "## Objective and status",
        "## Completed scope",
    )
    normalized_progress_current = " ".join(progress_current.split())
    normalized_release_current = " ".join(release_current.split())

    for content in (progress, release):
        assert "phase/07-fusion-evaluation" in content
        assert "Phase 8" in content and "not started" in content.lower()
        assert "pipeline verification only" in content.lower()
        assert "inconclusive" in content
        assert "validation-qualified" in content.lower()
        assert "not a public benchmark" in " ".join(content.lower().split())

    assert "Current phase | Phase 7" in normalized_progress_current
    assert "Status | Phase complete" in normalized_progress_current
    assert "Phase 8 status | Not started" in normalized_progress_current
    assert "phase/07-fusion-evaluation" in progress_current
    assert "phase-07-complete" in progress_current
    assert "PR [#21]" in normalized_progress_current
    assert "are merged" in normalized_progress_current

    assert "Status: **Phase complete**" in release_current
    assert "PR [#21]" in normalized_release_current
    assert "was squash-merged" in normalized_release_current
    assert "2465f8de67be7638670f9d30c1198ff76a60d17c" in normalized_release_current
    assert "phase-07-complete" in normalized_release_current
    assert "Phase 8 has not started" in normalized_release_current
    assert "Implementation complete — awaiting PR review" not in release_current

    assert "supervised-75-anomaly-25-t0.700" in release
    assert "fusion missed all held-out" in release.lower()
    assert "Historical Phase 5/6 frozen test reused: no" in " ".join(release.split())
    assert "ADR 0016" in release
    assert "Detection results, alerts, explanations" in release
    assert "not a public benchmark" in " ".join(release.split())
