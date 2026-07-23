"""Regression tests for truthful Phase 10 implementation-review status."""

from pathlib import Path

PROJECT_ROOT = Path(__file__).parents[2]


def _section(content: str, start: str, end: str) -> str:
    """Return one explicitly bounded Markdown section."""
    return content.split(start, maxsplit=1)[1].split(end, maxsplit=1)[0]


def test_readme_records_phase_ten_without_starting_phase_eleven() -> None:
    content = (PROJECT_ROOT / "README.md").read_text(encoding="utf-8")
    current = _section(content, "## Current status", "## Planned architecture")
    normalized = " ".join(current.split())

    assert "Phases 0–9 are complete" in current
    assert "phase/09-hypothesis-engine" in current
    assert "PR [#28]" in current
    assert "ffdd7639b60d944b19d70096e1ff38de0d8761f8" in current
    assert "phase-09-complete" in current
    assert "observed event time separate" in normalized
    assert "Phase 10" in normalized and "awaits pull-request review" in normalized
    assert "Phase 11 is **Not started**" in normalized
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
    assert "awaiting pull-request review" not in current
    assert "No operation trains, activates, or replaces a model" in normalized
    assert "retraining_candidate" in normalized


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


def test_progress_and_release_record_phase_ten_without_phase_eleven_scope() -> None:
    progress = (PROJECT_ROOT / "docs/codex_progress.md").read_text(encoding="utf-8")
    release = (PROJECT_ROOT / "docs/releases/phase-10.md").read_text(encoding="utf-8")

    progress_current = _section(
        progress,
        "## Current state",
        "## Phase 10 implementation checkpoint",
    )
    release_current = _section(
        release,
        "## Objective and status",
        "## Completed scope",
    )
    normalized_progress_current = " ".join(progress_current.split())
    normalized_release_current = " ".join(release_current.split())

    for content in (progress, release):
        assert "phase/10-case-feedback" in content
        assert "Phase 11" in content and "not started" in content.lower()
        assert "ground truth" in content.lower()

    assert "without claiming attack confirmation" in " ".join(progress.split())
    assert "not a confirmed attack" in release

    assert "Current phase | Phase 10" in normalized_progress_current
    assert (
        "Status | Implementation complete — awaiting PR review"
        in normalized_progress_current
    )
    assert (
        "Phase 10 status | Implementation complete — awaiting PR review"
        in normalized_progress_current
    )
    assert "Phase 11 status | Not started" in normalized_progress_current
    assert "phase/10-case-feedback" in progress_current
    assert "phase/11-runtime-replay" in progress_current

    assert "Status: **Implementation complete — awaiting PR review**" in release_current
    assert "Pull request: [#31]" in normalized_release_current
    assert "open and ready for review" in normalized_release_current
    assert "Completion tag: pending" in normalized_release_current
    assert "Phase 11: Not started" in normalized_release_current

    assert "ADR 0019" in release
    assert "retraining_candidate" in release
    assert "frozen-test" in release
    assert "not benchmark ground truth" in release
    assert "does not train" in release
